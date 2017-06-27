#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91192);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/18 15:32:28 $");

  script_cve_id("CVE-2015-4193");
  script_osvdb_id(137440);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun75294");

  script_name(english:"Cisco IOS XR OpenSSH Module SSH Login Channel Identifier DoS");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IOS XR software running on the remote device is
affected by a denial of service vulnerability in the OpenSSH module
due to improper validation of the channel identifier during an SSH
handshake negotiation. An authenticated, remote attacker can exploit
this issue, via a crafted SSH packet with an invalid channel
identifier, to reset the SSH login process.");
  # https://quickview.cloudapps.cisco.com/quickview/bug/CSCun75294
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c76c5b5d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCun75294.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencie("cisco_ios_xr_version.nasl","ssh_detect.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
flag     = FALSE;

if (ver_compare(ver:version, fix:"5.1.3", strict:FALSE)<0)
{
  flag = TRUE;
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

# Check for ssh, grab port. Not dependant on login, so vuln
# version will be detected whether from SSH or SNMP
ssh = get_service(svc:"ssh");

if (flag && ssh)
{
  report =
    '\n  Cisco bug ID      : CSCun75294' +
    '\n  Installed release : ' + version +
    '\n';
  security_report_v4(port:ssh, extra:report, severity:SECURITY_WARNING);
}
else exit(0, "The host is running a vulnerable version of 
Cisco IOS XR software (" + version + ") but is not affected 
because the SSH server does not appear to be enabled.");
