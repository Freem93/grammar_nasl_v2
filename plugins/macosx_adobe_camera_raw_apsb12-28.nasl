#TRUSTED 1f5e34f49b20559e5216d9b7d1515f4f1cc69b6dd59a848afb5556a31f6af7538f86ecdd7b7920d7c5309b6c1c7cb090b3e5080e4003ec150a0035d364abde8858355aea33354e4cf1f23eb81d75462086079f436ab0955bd4f08ea3473cdad0fb89468f62e3df11309aff4f47a4e77dfd14f247ee1cad7f4390108feda87ad7e46fc05c95de185d160d61dc3ddeb7eef8f4eb3413a7e059c9b394fa9da654b324232779a2444dca6a1630a9d49c63ff54d506dd8c7acd99d48f98a999512ecd614e6524f5a6f14fb9adc4f8f85e5b3cbbb3a67870f5b805b15313f8d1fbb12f7dd2df05071cc49363336c3ee7ddda30ae74a0889f9e67a12209c0d67c60310fa38d874d9353837b3cd66a7ec09145c43c954bfae6a4310ee08ff7296e4b043a2b2db975a20c6198af01419aea9edee6bbff2b78199b96072b63bc2a94f115a91dd3b7054d688782f6ea210fb0208f5c06beb9e360a8d56e384fc2622187d5a00d35615d5dc197eb02151831af2acb16ca3e6192e2b62db597de96c8da65471c37065a9617c90310965ca4812afe220cf5c20a098a7f1775577ee644e627983840421be98c3f6f8bf2dfa34a856b7458f4eed2c31c8a1ed36d001aacc03eecff9738770f0a17a4edcd9a4d24151637397cecba76bed518229eb03da6f37b8daa5b0204439c862d409d23062601d26a15a992f8046b33c55eb5a2f358a110bdd6
#
# (C) Tenable Network Security, Inc.
#


include ("compat.inc");

if (description)
{
  script_id(69347);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/08/14");

  script_cve_id("CVE-2012-5679", "CVE-2012-5680");
  script_bugtraq_id(56922, 56924);
  script_osvdb_id(88389, 88390);

  script_name(english:"Adobe Camera Raw Plugin Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of plug-in");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a software plugin installed that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the Adobe Camera Raw plugin installed on the remote host
is affected by the following vulnerabilities :

  - A flaw exists when processing an LZW compressed TIFF
    image that can be exploited to cause a heap-based buffer
    underflow via a specially crafted LZW code within an
    image row strip. (CVE-2012-5679)

  - An integer overflow error exists when allocating memory
    during TIFF image processing that can be exploited to
    cause a heap-based buffer overflow via specially crafted
    image dimensions. (CVE-2012-5680)

These vulnerabilities can be exploited by tricking a user into opening a
specially crafted file and could allow an attacker to execute arbitrary
code."
  );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2012-31/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-28.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Camera Raw Plug-In 6.7.1 / 7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:camera_raw");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

cmd = 'find "/Library/Application Support/Adobe/Plug-Ins" -name CS[56] -mindepth 1 -maxdepth 1 -type d';
dirs = exec_cmd(cmd:cmd);
if (isnull(dirs)) audit(AUDIT_NOT_INST, 'Adobe Photoshop Camera Raw');

report = '';

foreach dir (split(dirs, keep:FALSE))
{
  plist = dir + '/File Formats/Camera Raw.plugin/Contents/Info.plist';

  cmd =
    'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleVersion | ' +
    'tail -n 1 | ' +
    'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';

  version = exec_cmd(cmd:cmd);
  if (!isnull(version))
    version = str_replace(find:'f', replace:'.', string:version);

  not_vuln_list = make_list();
  if (!isnull(version) && version =~ '^[0-9\\.]+$')
  {
    if (version =~ "^6(\.|$)" && ver_compare(ver:version, fix:"6.7.1", strict:FALSE) == -1)
      fix = "6.7.1";
    else if (version =~ "^7(\.|$)" && ver_compare(ver:version, fix:"7.3", strict:FALSE) == -1)
      fix = "7.3";

    if (fix != '')
    {
      report += '\n  Path              : ' + dir +
                '\n  Installed version : ' + version +
                '\n  Fixed version     : ' + fix + '\n';
      if (!thorough_tests) break;
    }
    else not_vuln_list = make_list(not_vuln_list, version);
  }
}

if (report != '')
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Adobe Photoshop Camera Raw",
           join(not_vuln_list, sep:'/'));
