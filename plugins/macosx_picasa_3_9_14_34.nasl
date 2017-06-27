#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65926);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/11 17:10:19 $");

  script_cve_id("CVE-2009-2285");
  script_bugtraq_id(35451, 58613);
  script_osvdb_id(55265, 91508);
  script_xref(name:"EDB-ID", value:"10205");

  script_name(english:"Google Picasa < 3.9 Build 3.9.14.34 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Google Picasa");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a photo organization application that
is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Google Picasa is earlier than 3.9 Build
3.9.14.34.  As such, it is affected by the following vulnerabilities:

 - A buffer underflow vulnerability exists in the
   'LZWDecodeCompat' function in the LibTIFF library. An
   attacker could exploit this issue through the use of a
   specially crafted TIFF image, potentially causing a
   denial of service. (CVE-2009-2285)

 - A sign-extension flaw exists that is triggered by the
   'biBitCount' field that is not properly validated when
   processing the BMP color table.  An attacker could
   exploit this issue though a specially crafted BMP image,
   potentially causing a heap-based buffer overflow
   resulting in a denial of service or arbitrary code
   execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.google.com/picasa/answer/53209");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Picasa 3.9 Build 3.9.14.34 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:picasa");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("macosx_picasa_installed.nasl");
  script_require_keys("MacOSX/Picasa/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Google Picasa";

kb_base = "MacOSX/Picasa";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
version_ui = get_kb_item_or_exit(kb_base+"/Version_UI", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

fix = '3.9.14.34';
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 3.9 Build 3.9.14.34\n';
    security_hole(port:0, extra:info);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version_ui, path);
