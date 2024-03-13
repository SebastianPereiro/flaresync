package main

import (
	"cloudflareparser"
	"context"
	"flag"
	"fmt"
	"gcp"
	"os"
	"reflect"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/coralogix/go-coralogix-sdk"
	log "github.com/sirupsen/logrus"
)

var (
	// Command line flags
	gcpProject string
	gcpPolicy  string
	debug      bool
	// Coralogix creds
	coralogix_app_name       string = os.Getenv("CORALOGIX_APP_NAME")
	coralogix_key_gsm_name   string = os.Getenv("CORALOGIX_KEY_GSM_NAME")
	coralogix_subsystem_name        = "flaresync"
	// Shared error var
	err error
)

func init() {
	flag.StringVar(&gcpProject, "project", "", "Google Cloud Project")
	flag.StringVar(&gcpPolicy, "policy", "", "Cloud Armor policy name")
	flag.BoolVar(&debug, "debug", false, "Add additional debugging output")
}

// Show usage options if no project/policy specified
func customHelp() {
	fmt.Println("Usage: flaresync [OPTIONS]")
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println()
}

func main() {
	// Initialize exit routine (this allows the app to finish all deferred functions)
	var exitCode int
	defer func() { os.Exit(exitCode) }()

	// Check the cmd line args
	flag.Parse()
	if (gcpProject == "") || (gcpPolicy == "") {
		customHelp()
		exitCode = 1
		return
	}

	// Debug
	if debug {
		log.SetLevel(log.DebugLevel)
		coralogix.SetDebug(true)
	}

	// Create the main context
	ctx := context.Background()

	// If we have CORALOGIX_KEY_GSM_NAME and CORALOGIX_APP_NAME env variables defined, enable Coralogix logging
	log.WithFields(log.Fields{
		"timestamp":     time.Now(),
		"unixtimestamp": time.Now().UnixNano(),
		"project":       gcpProject,
	}).Debug("Enabling logging to Coralogix")
	var sm_client *secretmanager.Client
	sm_client, err = secretmanager.NewClient(ctx)
	if err != nil {
		log.WithFields(log.Fields{
			"timestamp":     time.Now(),
			"unixtimestamp": time.Now().UnixNano(),
			"project":       gcpProject,
		}).Errorf("Failed to create Secret Manager client: %v", err)
		exitCode = 1
		return
	}
	defer sm_client.Close()
	if coralogix_key_gsm_name != "" && coralogix_app_name != "" {
		// Get Coralogix credentials from the secret name obtained from ENV
		// Access the secret from Secret Manager.
		accessRequest := &secretmanagerpb.AccessSecretVersionRequest{
			Name: coralogix_key_gsm_name + "/versions/latest",
		}

		coralogix_private_key, err := sm_client.AccessSecretVersion(ctx, accessRequest)
		if err != nil {
			log.WithFields(log.Fields{
				"timestamp":     time.Now(),
				"unixtimestamp": time.Now().UnixNano(),
				"project":       gcpProject,
			}).Errorf("Failed to access secret version: %v", err)
			exitCode = 1
			return
		}

		// Initialise logging to Coralogix
		// Coralogix docs:
		// https://coralogix.com/docs/go/
		// https://pkg.go.dev/github.com/coralogix/go-coralogix-sdk?utm_source=godoc#section-readme
		CoralogixHook := coralogix.NewCoralogixHook(
			string(coralogix_private_key.Payload.Data),
			coralogix_app_name,
			coralogix_subsystem_name,
		)
		log.AddHook(CoralogixHook)
		defer CoralogixHook.Close()
	}

	log.WithFields(log.Fields{
		"timestamp":     time.Now(),
		"unixtimestamp": time.Now().UnixNano(),
		"project":       gcpProject,
	}).Infof("Starting flaresync for policy: %v", gcpPolicy)

	// get the actual ETag and ranges from CF:
	cf_etag, cf_networks, err := cloudflareparser.ParseCloudflareJSON()
	if err != nil {
		log.WithFields(log.Fields{
			"timestamp":     time.Now(),
			"unixtimestamp": time.Now().UnixNano(),
			"project":       gcpProject,
		}).Errorf("Error getting CloudFlare networks and/or ETag: %v", err)
		exitCode = 1
		return
	}
	cf_networks_len := len(cf_networks) // we'll use this var later several times
	log.WithFields(log.Fields{
		"timestamp":     time.Now(),
		"unixtimestamp": time.Now().UnixNano(),
		"project":       gcpProject,
	}).Info("CF ETag is: ", cf_etag)
	for _, val := range cf_networks { // just for debugging purposes
		log.WithFields(log.Fields{
			"timestamp":     time.Now(),
			"unixtimestamp": time.Now().UnixNano(),
			"project":       gcpProject,
		}).Debug(val)
	}

	// prepare SecurityPolicies GCP client
	client, err := compute.NewSecurityPoliciesRESTClient(ctx)
	if err != nil {
		log.WithFields(log.Fields{
			"timestamp":     time.Now(),
			"unixtimestamp": time.Now().UnixNano(),
			"project":       gcpProject,
		}).Errorf("Failed to create Compute Engine client: %v", err)
		exitCode = 1
		return
	}
	defer client.Close()

	// get the policy
	policy, err := gcp.GetCloudArmorPolicy(ctx, client, gcpProject, gcpPolicy)
	if err != nil {
		log.WithFields(log.Fields{
			"timestamp":     time.Now(),
			"unixtimestamp": time.Now().UnixNano(),
			"project":       gcpProject,
		}).Errorf("Failed to get the security policy state: %v", err)
		exitCode = 1
		return
	}

	// get etag and description for the current GCP policy
	ca_etag, ca_description := policy.GetFingerprint(), policy.GetDescription()
	log.WithFields(log.Fields{
		"timestamp":     time.Now(),
		"unixtimestamp": time.Now().UnixNano(),
		"project":       gcpProject,
	}).Infof("Found this CF ETag on GCP policy: %v", ca_description)

	// if the description i.e ca_etag on gcp policy and cf_etag are equal - exit without errors
	if ca_description == cf_etag {
		log.WithFields(log.Fields{
			"timestamp":     time.Now(),
			"unixtimestamp": time.Now().UnixNano(),
			"project":       gcpProject,
		}).Info("The policy and CloudFlare have the same ETags, exiting")
		exitCode = 0
		return
	}

	// if the policy description and cf_etag are different - update the policy

	// prepare variables
	// default settings for policy rules
	rule_description := "cloudflare - dont change"
	action := "allow"
	ver := "SRC_IPS_V1"
	// get the number of CF rules in the current GCP policy
	policy_rules_number := 0
	for _, v := range policy.Rules {
		if v.Description != nil && *v.Description == rule_description {
			policy_rules_number++
		}
	}
	log.WithFields(log.Fields{
		"timestamp":     time.Now(),
		"unixtimestamp": time.Now().UnixNano(),
		"project":       gcpProject,
	}).Debug("Found ", policy_rules_number, " CF rules in the current policy")

	// calculcate the number of rules we need to store CF networks (GCP limit is 10 networks per rule)
	rulesNeeded := (cf_networks_len + 9) / 10
	log.WithFields(log.Fields{
		"timestamp":     time.Now(),
		"unixtimestamp": time.Now().UnixNano(),
		"project":       gcpProject,
	}).Debug("We need ", rulesNeeded, "for CF networks")

	// decide which list or rules is bigger and assign rulesCounter to it for later iteration
	// rulesCounter := max(policy_rules_number, cf_networks_len)
	rulesCounter := max(policy_rules_number, rulesNeeded)
	log.WithFields(log.Fields{
		"timestamp":     time.Now(),
		"unixtimestamp": time.Now().UnixNano(),
		"project":       gcpProject,
	}).Debug("The rules counter is set to: ", rulesCounter)
	// set left and right pointers to indexes in the CF networks slice
	l, r := 0, 0
	// Case 1: there are now rules in the policy yet
	if policy_rules_number == 0 {
		// iterate over the previously calculated number of required rules
		for i := 0; i < rulesNeeded; i++ {
			var prio int32 = int32(i)
			// calculate the right index pointer: move 10 positions to the right or to the end of the network slice
			r = l + 10
			if r > cf_networks_len {
				r = cf_networks_len
			}
			log.WithFields(log.Fields{
				"timestamp":     time.Now(),
				"unixtimestamp": time.Now().UnixNano(),
				"project":       gcpProject,
			}).Debug("l and r values are: ", l, r)
			// form a rule
			rule := &computepb.SecurityPolicyRule{
				Description: &rule_description,
				Action:      &action,
				Priority:    &prio,
				Match: &computepb.SecurityPolicyRuleMatcher{
					VersionedExpr: &ver,
					Config: &computepb.SecurityPolicyRuleMatcherConfig{
						// use r and l pointers to copy CF networks to the rule
						SrcIpRanges: cf_networks[l:r],
					},
				},
			}
			// push the rule to the policy
			log.WithFields(log.Fields{
				"timestamp":     time.Now(),
				"unixtimestamp": time.Now().UnixNano(),
				"project":       gcpProject,
			}).Info("Adding new rules, batch number: ", i)
			err = gcp.AddCloudArmorRule(ctx, client, gcpProject, gcpPolicy, rule)
			if err != nil {
				log.WithFields(log.Fields{
					"timestamp":     time.Now(),
					"unixtimestamp": time.Now().UnixNano(),
					"project":       gcpProject,
				}).Errorf("Failed to populate the policy with new rules: %v", err)
				exitCode = 1
				return
			}
			// move the left index pointer 10 positions to the right
			l = +10
		}
	} else {
		// Case 2: we already have rules in the policy and we want replace them with new ones
		for i := 0; i < rulesCounter; i++ {
			var prio int32 = int32(i)
			// Subcase: GCP policy already has a rule of a given priority - patch it
			if (i < rulesNeeded) && (i < policy_rules_number) {
				log.WithFields(log.Fields{
					"timestamp":     time.Now(),
					"unixtimestamp": time.Now().UnixNano(),
					"project":       gcpProject,
				}).Info("Patching rule number: ", prio)
				r = l + 10
				if r > cf_networks_len {
					r = cf_networks_len
				}
				log.WithFields(log.Fields{
					"timestamp":     time.Now(),
					"unixtimestamp": time.Now().UnixNano(),
					"project":       gcpProject,
				}).Debug("l and r values are: ", l, r)
				// compare CF network list with already present rule
				// use new right index pointer (left is always 0 for comparison with the current rule)
				r2 := 0
				if r == 10 {
					r2 = 10
				} else {
					r2 = r % 10
				}
				// easy compare with reflect.DeepEqual function
				// first condition to check: r and r2 (number of IP ranges in rules) must be equal, otherwise continue with rule update
				if (r == r2) && (reflect.DeepEqual(cf_networks[l:r], policy.Rules[i].Match.Config.SrcIpRanges[0:r2])) {
					log.WithFields(log.Fields{
						"timestamp":     time.Now(),
						"unixtimestamp": time.Now().UnixNano(),
						"project":       gcpProject,
					}).Info("... not patching, rules are the same")
					// move the left index pointer 10 positions to the right
					l = +10
					continue
				}
				rule := &computepb.SecurityPolicyRule{
					Description: &rule_description,
					Action:      &action,
					Priority:    &prio,
					Match: &computepb.SecurityPolicyRuleMatcher{
						VersionedExpr: &ver,
						Config: &computepb.SecurityPolicyRuleMatcherConfig{
							// use r and l pointers to copy CF networks to the rule
							SrcIpRanges: cf_networks[l:r],
						},
					},
				}
				err = gcp.PatchCloudArmorRule(ctx, client, gcpProject, gcpPolicy, prio, rule)
				if err != nil {
					log.WithFields(log.Fields{
						"timestamp":     time.Now(),
						"unixtimestamp": time.Now().UnixNano(),
						"project":       gcpProject,
					}).Errorf("Failed to patch the policy rule: %v", err)
					exitCode = 1
					return
				}
				// Subcase: GCP policy has less rules than CF list - add new rules
			} else if (i < rulesNeeded) && (i >= policy_rules_number) {
				log.WithFields(log.Fields{
					"timestamp":     time.Now(),
					"unixtimestamp": time.Now().UnixNano(),
					"project":       gcpProject,
				}).Info("Adding new rule number: ", prio)
				r = l + 10
				if r > cf_networks_len {
					r = cf_networks_len
				}
				log.WithFields(log.Fields{
					"timestamp":     time.Now(),
					"unixtimestamp": time.Now().UnixNano(),
					"project":       gcpProject,
				}).Debug("l and r values are: ", l, r)
				rule := &computepb.SecurityPolicyRule{
					Description: &rule_description,
					Action:      &action,
					Priority:    &prio,
					Match: &computepb.SecurityPolicyRuleMatcher{
						VersionedExpr: &ver,
						Config: &computepb.SecurityPolicyRuleMatcherConfig{
							// use r and l pointers to copy CF networks to the rule
							SrcIpRanges: cf_networks[l:r],
						},
					},
				}
				err = gcp.AddCloudArmorRule(ctx, client, gcpProject, gcpPolicy, rule)
				if err != nil {
					log.WithFields(log.Fields{
						"timestamp":     time.Now(),
						"unixtimestamp": time.Now().UnixNano(),
						"project":       gcpProject,
					}).Errorf("Failed to add a new rule to the policy: %v", err)
					exitCode = 1
					return
				}
				// Subcase: GCP policy has excessive rules - delete them
			} else {
				log.WithFields(log.Fields{
					"timestamp":     time.Now(),
					"unixtimestamp": time.Now().UnixNano(),
					"project":       gcpProject,
				}).Info("Removing rule number: ", prio)
				err = gcp.RemoveCloudArmorRule(ctx, client, gcpProject, gcpPolicy, prio)
				if err != nil {
					log.WithFields(log.Fields{
						"timestamp":     time.Now(),
						"unixtimestamp": time.Now().UnixNano(),
						"project":       gcpProject,
					}).Errorf("Failed to remove a rule from the policy: %v", err)
					exitCode = 1
					return
				}
			}
			// move the left index pointer 10 positions to the right
			l = +10
		}
	}

	// get the current policy's eTag after all operations
	policy, err = gcp.GetCloudArmorPolicy(ctx, client, gcpProject, gcpPolicy)
	if err != nil {
		log.WithFields(log.Fields{
			"timestamp":     time.Now(),
			"unixtimestamp": time.Now().UnixNano(),
			"project":       gcpProject,
		}).Errorf("Failed to get the security policy state: %v", err)
		exitCode = 1
		return
	}
	ca_etag = policy.GetFingerprint()

	// update the policy with a new CloudFlare eTag (i.e. the policy Description)
	policy = &computepb.SecurityPolicy{
		Description: &cf_etag,
		Fingerprint: &ca_etag,
	}
	log.WithFields(log.Fields{
		"timestamp":     time.Now(),
		"unixtimestamp": time.Now().UnixNano(),
		"project":       gcpProject,
	}).Infof("Updating the policy description with ETag %v", cf_etag)
	err = gcp.PatchCloudArmorPolicy(ctx, client, gcpProject, gcpPolicy, policy)
	if err != nil {
		log.WithFields(log.Fields{
			"timestamp":     time.Now(),
			"unixtimestamp": time.Now().UnixNano(),
			"project":       gcpProject,
		}).Errorf("Failed to patch the security policy: %v", err)
		exitCode = 1
		return
	}

	// exit the app
	log.WithFields(log.Fields{
		"timestamp":     time.Now(),
		"unixtimestamp": time.Now().UnixNano(),
		"project":       gcpProject,
	}).Info("Stopping flaresync")
}
