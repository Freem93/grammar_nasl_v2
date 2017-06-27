#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91674);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_osvdb_id(
    138971,
    138972,
    138973,
    138974,
    138975,
    138976,
    138977,
    138978
  );

  script_name(english:"Palo Alto Networks PAN-OS 7.0.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
7.0.7. It is, therefore, affected by multiple vulnerabilities :

  - A flaw exists in the passive firewall where a VM-series
    ESXi configuration processes and forwards traffic. No
    other details are available. (VulnDB 138971)

  - An unspecified overflow condition exists due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (VulnDB 138972)

  - An unspecified underflow condition exists due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    have an unspecified impact. No other details are
    available. (VulnDB 138973)

  - A flaw exists in the API interface due to sending
    inappropriate responses to special requests. An
    unauthenticated, remote attacker can exploit this to
    have an unspecified impact. No other details are
    available. (VulnDB 138974)

  - A flaw exists in the command line interface (CLI) that
    allows a local attacker to improperly execute code. No
    other details are available. (VulnDB 138975)

  - A flaw exists that is related to the management plane
    account restrictions. An authenticated, remote attacker
    can exploit this to cause a denial of service condition.
    (VulnDB 138976)

  - A flaw exists when handling improperly formatted API
    calls to Panorama. An unauthenticated, remote attacker
    can exploit this to cause a system daemon to stop
    responding, resulting in a denial of service.
    (VulnDB 138977)

  - A flaw exists when handling HTTP GET packets that allows
    an unauthenticated, remote attacker to bypass the
    firewall even when the URL filtering profile was
    configured to block packets in this URL category.
    (VulnDB 138978)");
  #https://www.paloaltonetworks.com/documentation/71/pan-os/pan-os-release-notes/pan-os-7-1-0-addressed-issues#60991
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9e38843");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
vuln = '7.0.7';
fix = '7.1.0';

# Ensure sufficient granularity.
if (version !~ "^\d+\.\d+") audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

# Compare version to vuln and report as needed.
if (ver_compare(ver:version, fix:vuln, strict:FALSE) == 0)
{
  report =
    '\n  Installed version : ' + full_version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, extra:report, port:0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
