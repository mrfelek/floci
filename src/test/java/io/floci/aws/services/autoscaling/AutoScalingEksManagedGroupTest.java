package io.floci.aws.services.autoscaling;

import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.services.autoscaling.model.AsgInstance;
import io.floci.aws.services.autoscaling.model.AutoScalingGroup;
import io.floci.aws.services.ec2.Ec2Service;
import io.floci.aws.services.ec2.model.Instance;
import io.floci.aws.services.ec2.model.Placement;
import io.floci.aws.services.ec2.model.Subnet;
import io.floci.aws.services.elbv2.ElbV2Service;
import io.floci.aws.services.elbv2.model.TargetDescription;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/**
 * The groups EKS keeps for its managed node groups. Floci runs one node per cluster, so the groups of a cluster's
 * node groups all hold that node: Auto Scaling adds it, registers it with the target groups attached to each group,
 * and keeps it in a target group as long as one group holding it has that target group attached.
 */
class AutoScalingEksManagedGroupTest {

    private static final String REGION = "us-east-1";
    private static final String FIRST = "eks-workers-1a2b3c4d";
    private static final String SECOND = "eks-batch-5e6f7a8b";
    private static final String NODE = "i-0123456789abcdef0";
    private static final Map<String, String> TAGS = Map.of(
            "eks:cluster-name", "shop",
            "eks:nodegroup-name", "workers",
            "k8s.io/cluster-autoscaler/enabled", "true",
            "k8s.io/cluster-autoscaler/shop", "owned");

    private final ElbV2Service targets = mock(ElbV2Service.class);
    private final Ec2Service ec2 = mock(Ec2Service.class);
    private final AutoScalingService service = new AutoScalingService(targets, null);

    AutoScalingEksManagedGroupTest() {
        service.regionResolver = new RegionResolver(REGION, "000000000000");
        service.ec2Service = ec2;
    }

    @Test
    void theGroupMirrorsTheNodeGroupWithoutALaunchSourceAndIsCreatedOnce() {
        Subnet subnet = new Subnet();
        subnet.setSubnetId("subnet-a");
        subnet.setAvailabilityZone("us-east-1a");
        when(ec2.describeSubnets(REGION, List.of("subnet-a", "subnet-unknown"), null)).thenReturn(List.of(subnet));

        service.createEksManagedGroup(REGION, FIRST, 1, 3, 2, List.of("subnet-a", "subnet-unknown"), TAGS);

        AutoScalingGroup group = service.requireGroup(REGION, FIRST);
        assertTrue(group.isEksManaged());
        assertEquals("arn:aws:autoscaling:us-east-1:000000000000:autoScalingGroup:" + FIRST,
                group.getAutoScalingGroupArn());
        assertEquals(1, group.getMinSize());
        assertEquals(3, group.getMaxSize());
        assertEquals(2, group.getDesiredCapacity());
        assertEquals(List.of("us-east-1a"), group.getAvailabilityZones());
        assertEquals(List.of("subnet-a", "subnet-unknown"), group.getSubnetIds());
        assertEquals(TAGS, group.getTags());
        assertEquals(Map.of("eks:cluster-name", true, "eks:nodegroup-name", true,
                "k8s.io/cluster-autoscaler/enabled", true, "k8s.io/cluster-autoscaler/shop", true),
                group.getTagPropagateAtLaunch());
        assertEquals(List.of("Default"), group.getTerminationPolicies());
        assertNull(group.getLaunchConfigurationName());
        assertNull(group.getLaunchTemplateId());
        assertNull(group.getLaunchTemplateName());
        assertNull(group.getMixedInstancesPolicy());
        assertEquals(List.of(), group.getInstances());

        // Restoring a node group creates its group again; one that exists is left as it is.
        service.createEksManagedGroup(REGION, FIRST, 0, 5, 0, List.of(), Map.of());

        assertSame(group, service.requireGroup(REGION, FIRST));
        assertEquals(1, group.getMinSize());
        assertEquals(3, group.getMaxSize());
        assertEquals(2, group.getDesiredCapacity());
        assertEquals(TAGS, group.getTags());
    }

    @Test
    void anAddedNodeIsInServiceAndRegisteredWithTheTargetGroupsAlreadyAttached() {
        service.createEksManagedGroup(REGION, FIRST, 1, 3, 2, List.of(), TAGS);
        service.attachLoadBalancerTargetGroups(REGION, FIRST, List.of("tg-attached"));
        service.attachTrafficSources(REGION, FIRST, List.of(
                new AutoScalingService.TrafficSourceIdentifier("tg-source", "elbv2"),
                new AutoScalingService.TrafficSourceIdentifier("lattice-service", "vpc-lattice")));
        verifyNoInteractions(targets);

        service.addEksManagedInstance(REGION, FIRST, node());
        service.addEksManagedInstance(REGION, FIRST, node());

        List<AsgInstance> members = service.requireGroup(REGION, FIRST).getInstances();
        assertEquals(1, members.size());
        AsgInstance member = members.getFirst();
        assertEquals(NODE, member.getInstanceId());
        assertEquals("InService", member.getLifecycleState());
        assertEquals("Healthy", member.getHealthStatus());
        assertEquals("us-east-1b", member.getAvailabilityZone());
        assertEquals("m5.large", member.getInstanceType());
        assertNull(member.getLaunchTemplateId());
        verify(targets).registerTargets(eq(REGION), eq("tg-attached"), only(NODE));
        verify(targets).registerTargets(eq(REGION), eq("tg-source"), only(NODE));
        verifyNoMoreInteractions(targets);
    }

    @Test
    void attachingAndDetachingTargetGroupsRegistersAndDeregistersTheNode() {
        service.createEksManagedGroup(REGION, FIRST, 1, 3, 2, List.of(), TAGS);
        service.addEksManagedInstance(REGION, FIRST, node());

        service.attachLoadBalancerTargetGroups(REGION, FIRST, List.of("tg-a"));
        service.attachTrafficSources(REGION, FIRST, List.of(
                new AutoScalingService.TrafficSourceIdentifier("tg-b", null)));
        verify(targets).registerTargets(eq(REGION), eq("tg-a"), only(NODE));
        verify(targets).registerTargets(eq(REGION), eq("tg-b"), only(NODE));

        // Attached both ways, tg-a stays attached when one of them is detached.
        service.attachTrafficSources(REGION, FIRST, List.of(
                new AutoScalingService.TrafficSourceIdentifier("tg-a", "elbv2")));
        service.detachLoadBalancerTargetGroups(REGION, FIRST, List.of("tg-a"));
        verifyNoMoreInteractions(targets);

        service.detachTrafficSources(REGION, FIRST, List.of(
                new AutoScalingService.TrafficSourceIdentifier("tg-a", "elbv2"),
                new AutoScalingService.TrafficSourceIdentifier("tg-b", "elbv2")));

        verify(targets).deregisterTargets(eq(REGION), eq("tg-a"), only(NODE));
        verify(targets).deregisterTargets(eq(REGION), eq("tg-b"), only(NODE));
        verifyNoMoreInteractions(targets);
        assertEquals(List.of(NODE), memberIds(FIRST));
    }

    @Test
    void deletingAGroupLeavesTheSharedNodeInTheTargetGroupsAnotherGroupHolds() {
        service.createEksManagedGroup(REGION, FIRST, 1, 3, 2, List.of(), TAGS);
        service.createEksManagedGroup(REGION, SECOND, 1, 1, 1, List.of(), TAGS);
        service.addEksManagedInstance(REGION, FIRST, node());
        service.addEksManagedInstance(REGION, SECOND, node());
        service.attachLoadBalancerTargetGroups(REGION, FIRST, List.of("tg-first", "tg-shared"));
        service.attachLoadBalancerTargetGroups(REGION, SECOND, List.of("tg-shared"));
        clearInvocations(targets);

        service.deleteEksManagedGroup(REGION, FIRST);

        assertEquals(List.of(), service.describeAutoScalingGroups(REGION, List.of(FIRST)));
        assertEquals(List.of(NODE), memberIds(SECOND));
        verify(targets).deregisterTargets(eq(REGION), eq("tg-first"), only(NODE));
        verifyNoMoreInteractions(targets);

        service.deleteEksManagedGroup(REGION, SECOND);

        assertEquals(List.of(), service.describeAutoScalingGroups(REGION, null));
        verify(targets).deregisterTargets(eq(REGION), eq("tg-shared"), only(NODE));
        verifyNoMoreInteractions(targets);
        // The node is EKS's: deleting its groups terminates nothing.
        verifyNoInteractions(ec2);
    }

    private List<String> memberIds(String group) {
        return service.requireGroup(REGION, group).getInstances().stream().map(AsgInstance::getInstanceId).toList();
    }

    private static Instance node() {
        Instance node = new Instance();
        node.setInstanceId(NODE);
        node.setInstanceType("m5.large");
        node.setPlacement(new Placement("us-east-1b"));
        return node;
    }

    private static List<TargetDescription> only(String instanceId) {
        return argThat(described -> described.size() == 1 && instanceId.equals(described.getFirst().getId()));
    }
}
