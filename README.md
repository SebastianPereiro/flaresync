## Flaresync
This application synchronises Cloudflare egress [IP ranges](https://www.cloudflare.com/ips/) with GCP Cloud Armor policies.
It allows you to restrict incoming connections to your GKE ingresses to traffic that has been proxied by the Cloudflare WAF.
Run it daily as k8s CronJob.

#### How it works:
It gets the current Cloudflare IP ranges ETag and compares it with the GCP policy description. If the ETag is different, it updates the policy rules.

#### CLI flags:
```
  -debug
        Add additional debugging output
  -policy string
        Cloud Armor policy name
  -project string
        Google Cloud Project
```