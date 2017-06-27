#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71898);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/01/10 15:49:01 $");

  script_cve_id(
    "CVE-2013-5349",
    "CVE-2013-5357",
    "CVE-2013-5358",
    "CVE-2013-5359"
  );
  script_bugtraq_id(64466, 64467, 64468, 64470);
  script_osvdb_id(101228, 101229, 101230, 101231);

  script_name(english:"Google Picasa < 3.9 Build 137.119 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Google Picasa");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a photo organization application
that is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Google Picasa installed on the remote host is earlier
than 3.9 Build 137.119.  As such, it is affected by the following
vulnerabilities :

  - An integer underflow vulnerability exists when parsing
    Canon RAW CR2 files containing a JPEG tag with the value
    greater than 0xFF00 and the size smaller than 2.
    (CVE-2013-5349)

  - An integer overflow vulnerability exists due to parsing
    Canon RAW CR2 files with excessively large
    'StripByteCounts' TIFF tag. (CVE-2013-5357)

  - A memory corruption vulnerability exists due to a
    boundary error when parsing TIFF tags with the model set
    to 'DSLR-A100' and containing multiple sequences of
    0x100 and 0x14A tags. (CVE-2013-5358)

  - A buffer overflow vulnerability exists due to an error
    when parsing a specially crafted KDC file with a size
    of 71 bytes. (CVE-2013-5359)

Exploitation of these vulnerabilities could result in a denial of
service or arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.google.com/picasa/answer/53209");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2013-14/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Picasa 3.9.0 Build 137.119 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:picasa");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

fixed_ver = "3.9.137.119";

if (ver_compare(ver:version, fix:fixed_ver, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 3.9 Build 137.119\n';
    security_hole(port:0, extra:info);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version_ui, path);
