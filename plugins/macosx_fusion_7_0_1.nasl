#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84218);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2015-2341");
  script_bugtraq_id(75094);
  script_osvdb_id(123094);
  script_xref(name:"VMSA", value:"2015-0004");

  script_name(english:"VMware Fusion 6.x < 6.0.6 / 7.x < 7.0.1 RPC Command DoS");
  script_summary(english:"Checks the VMware Fusion version.");

  script_set_attribute(attribute:"synopsis", value:
"A VMware product installed on the remote host is affected by a denial
of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion installed on the remote Mac OS X host is
version 6.x prior to 6.0.6 or 7.x prior to 7.0.1. It is, therefore,
affected by a denial of service vulnerability due to improper
validation of user-supplied input to a remote procedure call (RPC)
command. An unauthenticated, remote attacker can exploit this, via a
crafted command, to crash the host or guest operating systems.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0004.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Fusion version 6.0.6 / 7.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "MacOSX/Fusion/Version", "MacOSX/Fusion/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

version = get_kb_item_or_exit("MacOSX/Fusion/Version");
path = get_kb_item_or_exit("MacOSX/Fusion/Path");

fix = NULL;
if (version =~ "^6\." && ver_compare(ver:version, fix:"6.0.6", strict:FALSE) == -1)
  fix = '6.0.6';

else if (version =~ "^7\." && ver_compare(ver:version, fix:"7.0.1", strict:FALSE) == -1)
  fix = '7.0.1';

if(fix)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
      security_hole(port:0, extra:report);
    }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Fusion", version, path);
