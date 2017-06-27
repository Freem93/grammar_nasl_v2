#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84500);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id("CVE-2015-4217");
  script_osvdb_id(123706);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus29681");
  script_xref(name:"IAVA", value:"2015-A-0136");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu95676");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu96601");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150625-ironport");

  script_name(english:"Cisco Ironport Security Appliance Default Host Key Vulnerability");
  script_summary(english:"Checks if the remote host responds with a known key.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco security appliance uses a default host key that is
shared among all installations of the product. An unauthenticated,
remote attacker with knowledge of the private key can impersonate
other devices or perform a man-in-the-middle attack between this host
and other virtual security appliances.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150625-ironport
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b60640b6");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20150625-ironport.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_virtual_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_virtual_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_virtual_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("ssh_func.inc");
include("misc_func.inc");

port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);

host_key = get_kb_item("SSH/publickey/ssh-rsa/" + port);
if (empty_or_null(host_key))
  host_key = get_kb_item("SSH/publickey/ssh-dsa/" + port);

if (empty_or_null(host_key))
  exit(0, "Nessus was unable to obtain the host's key.");

default_keys = make_list(
  "AAAAB3NzaC1yc2EAAAADAQABAAABAQCmkCwuBsBk12gtO2niJivv8bZncl44dOq09SyVuPbTL8RfoKona01g0cyfiwdnqBmBW7P2CA+5V3gq0/rGOfJ5TpElTLK/F8od8zF5K0mhSE20FPCbTVigR4m2xij/fKI8h+jJMbYPEV82yIIGGG+802Q7pGR0p4CU0a9yNqFNhr52egJNWVj98O3jM8vdFw1eTogEEa7zkQO/YF1EQ9V+q5U1le0DbZ5vmgFIt/7nOersnnszYMdywPPWRtIJJveI8hbhfC9HZ7CQIXWPiYv1rrjGBdDX4LonE4kIMU3CCf/a4DH+rX4FGtKYdxiPlJS2TxV8Nv1PcIovj/aYdYlf",
  "AAAAB3NzaC1yc2EAAAADAQABAAABAQCqz7uUNZKJDvXz44PeixU/bQsJ3pziZP0FpO1AS4ANvOJ7aOsWMfhzvXnimMsRfMVPARoHTn6Q5EsW2jkgWo0qa6/HMlhc/196zEmvnIrNuvYvQiwHzIAzm3MlhZLbWYGUtPl4L1pQUsn4GAKc9OYqyub6kYBeKvNj3N+kGpTs6oXHpmy4qC8LsNOHwVREPN3/6q4D3tqGkO+x0LKXoIXxB/bHgelPbCdRSxKOnizudu6Gjj5UVLGhDU1Oy1bfzbvzNQG7bFx0ueAL/2FVVplICcj5fTHm9yqUcl/3We6TgaFAtL/lPqGpI1y0UAEvfNpmDp+wAztZAOY6FRA03cPh",
  "AAAAB3NzaC1yc2EAAAADAQABAAABAQDG3Yd4tfLqaj+Cu7D0BgwnYsexDSlb+loUfPalvfGPgWjF+HQiorytLRKVEf8SBHRjMiXX901gKPSKfyFvoAzMHlR8LtO0c9B1SoDdenWgRiYzu1G1z4baEq2YOSpt8yLrVc27jrdR1gf0NAXxHXQTKT5YfpvjEuDr25azKGQAHIe+17U70ruwcPeBGO/RGQ+aHn58DGbO8GKRsxhTZjO13SdgmpDoCQbWvMzgAqEPZNJqbZy7PA/3wKtpu5yYTFKUSmkBfOvCrHmA+POXl+F2Brg2/S7J4kbivacfNDEn5rlGuiY/On6E2Zj3nkI5x5r1OCasuh9cLdx++2/2bAf/"
);

vuln = FALSE;
foreach default_key (default_keys)
{
  if (default_key == host_key)
  {
    vuln = TRUE;
    break;
  }
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to verify that the remote host uses the following' +
      '\ndefault SSH public key :' +
      '\n  Key  : ' + host_key +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_HOST_NOT, "affected");
