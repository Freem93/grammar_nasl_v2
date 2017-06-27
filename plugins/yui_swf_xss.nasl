#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50495);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/01 20:05:52 $");

  script_cve_id("CVE-2010-4207", "CVE-2010-4208", "CVE-2010-4209");
  script_bugtraq_id(44420);
  script_osvdb_id(68875, 68876, 68877);

  script_name(english:"YUI charts.swf / swfstore.swf / uploader.swf XSS");
  script_summary(english:"Verifies MD5 checksums of affected SWF files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts at least one SWF file that is affected a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the YUI library of JavaScript utilities and controls
hosted on the remote web server includes at least one SWF file that is
affected by an unspecified cross-site scripting vulnerability.

An attacker can leverage this issue to inject arbitrary HTML or script
code into a user's browser to be executed within the security context
of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://yuilibrary.com/support/2.8.2/");
  script_set_attribute(attribute:"see_also", value:"http://moodle.org/mod/forum/discuss.php?d=160910");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/3.2.8/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Nov/48");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to YUI version 2.8.2 or later or replace the affected
files as described in the YUI advisory. Alternatively,

  - If using Bugzilla, upgrade to version 3.2.8 / 3.4.8 /
    3.6.2 / 3.7.3 or later.

  - If using Moodle, upgrade to version 1.9.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "bugzilla_detect.nasl", "moodle_detect.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, embedded:FALSE);

# Get a list of SWF files to check.
swf_files = make_list();

files = get_kb_list("www/"+port+"/content/extensions/swf");
if (!isnull(files))
{
  foreach file (files)
    if (
      report_paranoia > 1 ||
      egrep(pattern:"^.+/(charts|swfstore|uploader)\.swf$", string:file)
    ) swf_files = make_list(swf_files, file);
}

dirs = get_dirs_from_kb(appname:'Bugzilla', port:port, exit_on_fail:FALSE);
if (!isnull(dirs))
{
  foreach dir (dirs)
  {
    swf_files = make_list(
      swf_files,
      dir+'/js/yui/swfstore/swfstore.swf'
    );
  }
}

dirs = get_dirs_from_kb(appname:'Moodle', port:port, exit_on_fail:FALSE);
if (!isnull(dirs))
{
  foreach dir (dirs)
  {
    swf_files = make_list(
      swf_files,
      dir+'/lib/yui/charts/assets/charts.swf',
      dir+'/lib/yui/uploader/assets/uploader.swf'
    );
  }
}

if (thorough_tests)
{
  dir = '/yui';
  swf_files = make_list(
    swf_files,
    dir+'/build/charts/assets/charts.swf',
    dir+'/build/uploader/assets/uploader.swf',
    dir+'/build/swfstore/swfstore.swf'
  );
}

if (isnull(swf_files))
  audit(AUDIT_WEB_FILES_NOT, 'SWF', port);

# Verify the MD5 checksums of each possible file.
chart = make_array();
chart['329254385eaa6d9c24da093d70680dd9'] = '2.4.0';
chart['57bec7baafc946b62eab55bd97857653'] = '2.4.1';
chart['7571ff3667b3b1a39d1f93faccf5a9cc'] = '2.5.0 / 2.5.1';
chart['8a3a3c628eb8c2b2829ccce65ba33075'] = '2.5.2';
chart['33eb7bfcf62d02e7d79ffbaaceb9a603'] = '2.6.0';
chart['8890bf87a83994c857ae3fa4eea97de2'] = '2.7.0';
chart['59c6e2c9ae7de87f11dd3db3336de8b6'] = '2.8.0 / 2.8.1 PR1 / 2.8.1';

uploader = make_array();
uploader['90a9b50f35961f45b705966736466485'] = '2.5.0';
uploader['85c7520f4580aaf5bdba1d428121099d'] = '2.5.1 / 2.5.2';
uploader['bf36d6b72f172e758986292ffe6ccecf'] = '2.6.0';
uploader['02e3dab263ab0ed0d2a30bba9e091d96'] = '2.7.0';
uploader['52f36a13ac4ee2743531de3e29c0b55c'] = '2.8.0';
uploader['eeb5aa24c17afae286845bedb142da28'] = '2.8.1 PR1 / 2.8.1';

swfstore = make_array();
swfstore['f619420748b08a2d453c049ef190e2f3'] = '2.8.0 / 2.8.1 PR1 / 2.8.1';

info = "";

foreach swf_file (list_uniq(swf_files))
{
  res = http_send_recv3(method:"GET", item:swf_file, port:port, exit_on_fail:TRUE);
  if (!res[2]) continue;

  md5 = hexstr(MD5(res[2]));
  if (
    (
      report_paranoia > 1 ||
      ereg(pattern:"/charts\.swf$", string:swf_file)
    ) &&
    chart[md5]
  )
  {
    info += '\n  URL          : ' + build_url(port:port, qs:swf_file) +
            '\n  MD5 checksum : ' + md5 +
            '\n  Known match  : charts.swf from YUI ' + chart[md5] + '\n';
  }
  if (
    (
      report_paranoia > 1 ||
      ereg(pattern:"/uploader\.swf$", string:swf_file)
    ) &&
    uploader[md5]
  )
  {
    info += '\n  URL          : ' + build_url(port:port, qs:swf_file) +
            '\n  MD5 checksum : ' + md5 +
            '\n  Known match  : uploader.swf from YUI ' + uploader[md5] + '\n';
  }
  if (
    (
      report_paranoia > 1 ||
      ereg(pattern:"/swfstore\.swf$", string:swf_file)
    ) &&
    swfstore[md5]
  )
  {
    info += '\n  URL          : ' + build_url(port:port, qs:swf_file) +
            '\n  MD5 checksum : ' + md5 +
            '\n  Known match  : swfstore.swf from YUI ' + swfstore[md5] + '\n';
  }

  if (info && !thorough_tests) break;
}
if (!info) exit(0, "No affected SWF files were found on the web server on port "+port+".");

# Report findings.
set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if (report_verbosity > 0)
{
  if (max_index(split(info)) > 4)
  {
    s = 's';
    their = 'their';
  }
  else
  {
    s = '';
    their = 'its';
  }

  report =
    '\n' + 'Nessus identified the following affected file' + s + ' based on ' + their + ' MD5' +
    '\n' + 'checksum' + s + ' :' +
    '\n' + info;

  if (report_paranoia > 1)
    report +=
      '\n' + 'Note that the filename' + s + ' reported here may not match those reported in' +
      '\n' + 'the YUI advisory because the \'Report Paranoia\' scan option was set to' +
      '\n' + '\'Paranoid\'.\n';

  if (!thorough_tests)
    report +=
      '\n' + 'Note that Nessus stopped searching after the first file was found. To' +
      '\n' + 'report all possible files, enable the \'Perform thorough tests\'' +
      '\n' + 'setting and re-scan.' +
      '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
