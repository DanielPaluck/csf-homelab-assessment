# Running a NIST CSF 2.0 Self-Assessment on My Home Lab

I wanted hands-on GRC experience, not just reading about it, so I ran a full NIST Cybersecurity Framework 2.0 self-assessment against my own home lab and home network. This is the write-up: what I did, what I found, and what I changed.

## Why I did it
I administer identity and endpoints at an MSP during the day, so I am comfortable on the technical side of security. What I had not done was sit on the other side of the table and assess an environment against a framework the way a GRC analyst does. My home lab was a safe place to learn that, because I own it and I know it well. I picked CSF 2.0 over ISO 27001 for one practical reason: the CSF control text is public domain, so I can share the whole thing.

## How I ran it
I scored all 106 CSF 2.0 controls on a simple 0 to 3 scale, from "not implemented" to "fully implemented," against what I could actually show was true. To keep myself honest, I wrote a small read-only script that pulls real configuration from the server (firewall rules, SSH settings, patch status, logging, backups) so my ratings were grounded in evidence instead of memory. I also wrote a tool that downloads the official CSF control set, scores my worksheet, and generates the report and a risk register. Fourteen controls did not apply to a one-person setup, so I marked them out of scope rather than scoring them as failures.

## What the baseline showed
My first number was 1.16 out of 3. That stung a little, but it was fair, and the shape of it was the interesting part. My strongest areas were Protect and Recover. I segment my network, encrypt traffic, patch automatically, and keep working backups, so the hands-on controls I enjoy were in decent shape. My weakest areas were Identify and Govern, and almost none of that was missing technical work. It was missing paperwork. I had no written security policy, no asset or data inventory, and no risk register. I was doing the right things and could not prove any of it.

That gap, between doing something and being able to show you do it, turned out to be the whole lesson. It is most of what GRC is about.

## What I fixed
I worked the gap list from the top. I wrote a one-page security policy covering access, patching, backups, logging, and how I handle risk. I built inventories of my hardware, my services, and my data. I wrote an incident-response runbook so I am not improvising if something goes wrong. I started a simple log for vulnerabilities, threats, and changes. And I did the one thing I had been putting off: I actually tested a backup restore and wrote down the result, instead of assuming it would work.

Then I re-scored honestly. The number moved from 1.16 to 1.51, and the biggest gains were in Govern and Identify, exactly where the missing piece had been documentation.

## What is left
Detection is my weakest function and the next place I am investing: centralized logging and real host monitoring instead of relying on my gateway alone. I also want formal configuration baselines. Those are the next entries on the remediation plan.

## What I took away
Two things. First, an honest low score with a plan beats a flattering number I cannot defend. Second, a lot of real-world security risk is not a missing firewall, it is undocumented process, and closing that is cheaper and faster than people expect. I will take both of those into a security role.
