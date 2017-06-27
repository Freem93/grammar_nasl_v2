#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56961);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/28 15:25:46 $");

  script_name(english:"Adobe AIR Unsupported Version Detection (Mac OS X)");
  script_summary(english:"Checks the Adobe AIR version.");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Adobe AIR is installed on the remote Mac OS
X host.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Adobe AIR on the remote Mac OS X host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/programs/policies/supported.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Adobe AIR that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_air_installed.nasl");
  script_require_keys("MacOSX/Adobe_AIR/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


kb_base = "MacOSX/Adobe_AIR";
version = get_kb_item_or_exit(kb_base+"/Version");

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] <= 4)
{
  register_unsupported_product(product_name:'Adobe Air',
                               version:version, cpe_base:"adobe:air");

  if (report_verbosity > 0)
  {
    path = get_kb_item_or_exit(kb_base+"/Path");
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Supported version : 22.x\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version, path);
