package gcp

import (
	"context"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
)

func GetCloudArmorPolicy(ctx context.Context, client *compute.SecurityPoliciesClient, projectID, policyName string) (*computepb.SecurityPolicy, error) {
	req := &computepb.GetSecurityPolicyRequest{
		Project:        projectID,
		SecurityPolicy: policyName,
	}
	resp, err := client.Get(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func PatchCloudArmorPolicy(ctx context.Context, client *compute.SecurityPoliciesClient, projectID, policyName string, securityPolicy *computepb.SecurityPolicy) error {
	req := &computepb.PatchSecurityPolicyRequest{
		Project:                projectID,
		SecurityPolicy:         policyName,
		SecurityPolicyResource: securityPolicy,
	}

	op, err := client.Patch(ctx, req)
	if err != nil {
		return err
	}

	return op.Wait(ctx)
}

func AddCloudArmorRule(ctx context.Context, client *compute.SecurityPoliciesClient, projectID, policyName string, newRule *computepb.SecurityPolicyRule) error {
	req := &computepb.AddRuleSecurityPolicyRequest{
		Project:                    projectID,
		SecurityPolicy:             policyName,
		SecurityPolicyRuleResource: newRule,
	}

	op, err := client.AddRule(ctx, req)
	if err != nil {
		return err
	}

	return op.Wait(ctx)
}

func PatchCloudArmorRule(ctx context.Context, client *compute.SecurityPoliciesClient, projectID, policyName string, rulePriority int32, rule *computepb.SecurityPolicyRule) error {
	req := &computepb.PatchRuleSecurityPolicyRequest{
		Project:                    projectID,
		SecurityPolicy:             policyName,
		Priority:                   &rulePriority,
		SecurityPolicyRuleResource: rule,
	}

	op, err := client.PatchRule(ctx, req)
	if err != nil {
		return err
	}

	return op.Wait(ctx)
}

func RemoveCloudArmorRule(ctx context.Context, client *compute.SecurityPoliciesClient, projectID, policyName string, rulePrio int32) error {
	req := &computepb.RemoveRuleSecurityPolicyRequest{
		Project:        projectID,
		SecurityPolicy: policyName,
		Priority:       &rulePrio,
	}

	op, err := client.RemoveRule(ctx, req)
	if err != nil {
		return err
	}

	return op.Wait(ctx)
}
