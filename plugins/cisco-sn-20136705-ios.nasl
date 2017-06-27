#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71925);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/04/05 00:33:50 $");

  script_cve_id("CVE-2013-6705");
  script_bugtraq_id(64063);
  script_osvdb_id(100521);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh38133");

  script_name(english:"Cisco IOS Software IP Device Tracking DoS");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the IP Device Tracking function in Cisco IOS could
allow a remote, unauthenticated attacker to trigger a denial of service
condition resulting in a reload of the device. 

It should be noted that while the vendor describes a possible
workaround, this plugin does not test for the presence of that
workaround."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-6705
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ee3e444");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the Cisco Security Notice.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");


  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Per Cisco:
# Cisco IOS Software releases are affected:
# 15.0(1)EX and later.
# 15.1(1)XO and later.
# 15.2(1)E and later.

if ( version =~ '^15.0(1)EX($|[0-3]$)' ) flag++;
if ( version == '15.1(1)XO' ) flag++;
if ( version =~ '^15.2(1)E($|[01]$)' ) flag++;

if (flag)
{
  if(report_verbosity > 0)
  {
    report = '\n  Cisco Bug ID          : CSCuh38133' +
             '\n      Installed release : ' + version + '\n';
    security_warning(extra:report, port:0);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
