#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(80175);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/23 13:47:46 $");

  script_cve_id(
    "CVE-2010-2587",
    "CVE-2010-2588",
    "CVE-2010-2589",
    "CVE-2010-4092",
    "CVE-2010-4093",
    "CVE-2010-4187",
    "CVE-2010-4188",
    "CVE-2010-4189",
    "CVE-2010-4190",
    "CVE-2010-4191",
    "CVE-2010-4192",
    "CVE-2010-4193",
    "CVE-2010-4194",
    "CVE-2010-4195",
    "CVE-2010-4196",
    "CVE-2010-4306",
    "CVE-2010-4307",
    "CVE-2011-0555",
    "CVE-2011-0556",
    "CVE-2011-0557",
    "CVE-2011-0569"
  );
  script_bugtraq_id(
    44617,
    46316,
    46317,
    46318,
    46319,
    46320,
    46321,
    46324,
    46325,
    46326,
    46327,
    46328,
    46329,
    46330,
    46332,
    46333,
    46334,
    46335,
    46336,
    46338,
    46339
  );
  script_osvdb_id(
    68982,
    72507,
    72508,
    72509,
    72510,
    72511,
    72512,
    72513,
    72514,
    72515,
    72516,
    72997,
    72998,
    72999,
    73000,
    73001,
    73002,
    73003,
    73004,
    73005,
    73006
  );
  script_xref(name:"Secunia", value:"42112");

  script_name(english:"Adobe Shockwave Player <= 11.5.9.615 (APSB11-01) (Mac OS X)");
  script_summary(english:"Checks the version of Shockwave Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser plugin that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host contains a version of Adobe Shockwave Player
that is 11.5.9.615 or earlier. It is, therefore, affected by multiple
vulnerabilities :

  - Several unspecified errors exist in the 'dirapi.dll'
    module that allow arbitrary code execution.
    (CVE-2010-2587, CVE-2010-2588, CVE-2010-4188)

  - An error exists in the 'dirapi.dll' module related to
    an integer overflow that allows arbitrary code
    execution. (CVE-2010-2589)

  - It is reported that a use-after-free error exists in an
    unspecified compatibility component related to the
    'Settings' window and an unloaded, unspecified library.
    This error is reported to allow arbitrary code execution
    when a crafted, malicious website is visited.
    (CVE-2010-4092)

  - Unspecified errors exist that allow arbitrary code
    execution or memory corruption. The attack vectors is
    unspecified. (CVE-2010-4093, CVE-2010-4187,
    CVE-2010-4190, CVE-2010-4191, CVE-2010-4192,
    CVE-2010-4306, CVE-2011-0555)

  - An input validation error exists in the 'IML32' module
    that allows arbitrary code execution when processing the
    global color table size of a GIF image contained in a
    Director movie. (CVE-2010-4189)

  - An unspecified input validation error exists that allows
    arbitrary code execution through unspecified vectors.
    (CVE-2010-4193)

  - An unspecified input validation error exists in the
    'dirapi.dll' module that allows arbitrary code execution
    through unspecified vectors. (CVE-2010-4194)

  - An integer overflow error exists in the '3D Assets'
    module when parsing 3D assets containing the record
    type '0xFFFFFF45'. This error allows arbitrary code
    execution. (CVE-2010-4196)

  - An input validation error exists in the 'DEMUX' chunks
    parsing portion of the 'TextXtra.x32' module. This
    error allows arbitrary code execution. (CVE-2010-4195)

  - An unspecified buffer overflow error exists that allows
    arbitrary code execution through unspecified vectors.
    (CVE-2010-4307)

  - An error exists in the 'PFR1' chunks parsing portion
    of the 'Font Xtra.x32' module. This error allows
    arbitrary code execution. (CVE-2011-0556)

  - An unspecified integer overflow error exists that allows
    arbitrary code execution through unspecified vectors
    (CVE-2011-0557)

  - An error exists in the 'Font Xtra.x32' module related
    to signedness that allows arbitrary code execution.
    (CVE-2011-0569)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-078/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-079/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-080/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-01.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave 11.5.9.620 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("shockwave_player_detect_macosx.nbin");
  script_require_keys("installed_sw/Shockwave Player", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app = 'Shockwave Player';

get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver = install['version'];
path = install['path'];

if (ver_compare(ver:ver, fix:'11.5.9.615', strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed versions    : 11.5.9.620' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
