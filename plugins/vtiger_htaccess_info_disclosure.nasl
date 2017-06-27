#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30108);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2008-3458");
  script_bugtraq_id(27228);
  script_osvdb_id(40218);

  script_name(english:"vTiger CRM Directory File Disclosure");
  script_summary(english:"Tries to retrieve a directory listing");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows listing
of directory content," );
 script_set_attribute(attribute:"description", value:
"The remote instance of vTiger allows an unauthenticated attacker to
view the contents of application directories, which could lead to the
disclosure of sensitive information. 

Note that the solution does not prevent an attacker from retrieving
files by guessing their names, only obtaining a directory listing when
one is not otherwise available." );
 script_set_attribute(attribute:"see_also", value:"http://trac.vtiger.com/cgi-bin/trac.cgi/ticket/2107" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=567189" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to vTiger CRM 5.0.4 RC or later and if necessary rename the
file 'htaccess.txt' in the 'vtigerCRM' directory under the web
server's document root to '.htaccess'." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/28");
 script_cvs_date("$Date: 2016/05/09 15:53:04 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 81);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

# Some vTiger directories to check.
if (thorough_tests) subdirs = make_list(
  "/test/wordtemplatedownload",
  "/test",
  "/logs",                             # doesn't exist in v4.x
  "/storage"                           # doesn't exist in v4.x
);
else subdirs = make_list("/test/wordtemplatedownload");


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/vtiger", "/tigercrm", "/crm", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure we're dealing with vTiger.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it is...
  if (
    '/vtigercrm_icon.ico">' >< res &&
    '<!-- startscrmprint --><' >< res
  )
  {
    # Try to exploit the issue to view the contents of a couple of directories.
    foreach subdir (subdirs)
    {
      # Make sure we can't get the file ordinarily.
      r = http_send_recv3(method:"GET",item:string(dir, subdir, "/"), port:port, exit_on_fail: 1);
      res = r[2];

      # There's a problem if we get a directory listing.
      if ("<title>Index of "+dir+subdir+"</title>" >< res)
      {
        if (report_verbosity)
        {
          report = string(
            "\n",
            "Here is the directory listing that Nessus retrieved for vtiger CRM's\n",
            subdir, " directory :\n",
            "\n",
            res
          );
          security_warning(port:port, extra:report);
        }
        else security_warning(port);

        exit(0);
      }
    }
  }
}

