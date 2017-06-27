#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72036);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/19 00:18:13 $");

  script_cve_id("CVE-2014-1208");
  script_bugtraq_id(64994);
  script_osvdb_id(102197);
  script_xref(name:"VMSA", value:"2014-0001");

  script_name(english:"VMware Fusion 5.x < 5.0.1 VMX Process DoS (VMSA-2014-0001)");
  script_summary(english:"Checks version of VMware Fusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion 5.x installed on the remote Mac OS X host
is prior to 5.0.1.  It is, therefore, reportedly affected by a denial of
service vulnerability due to an issue with handling invalid ports that
could allow a guest user to crash the VMX process.");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Fusion 5.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "MacOSX/Fusion/Version");

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

fixed_version = '5.0.1';
if (
  version =~ "^5\." &&
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Fusion", version, path);
