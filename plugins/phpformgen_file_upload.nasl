#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21918);
  script_version("$Revision: 1.13 $");

  script_bugtraq_id(18768);
  script_osvdb_id(26951);

  script_name(english:"phpFormGenerator Arbitrary File Upload");
  script_summary(english:"Tries to execute arbitrary code using phpFormGenator");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an arbitrary file upload vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpFormGenerator, a PHP-based tool for
generating web forms. 

The version of phpFormGenerator installed on the remote host allows an
unauthenticated attacker to create forms supporting arbitrary file
uploads.  He can then leverage this issue to upload a file with
arbitrary code and execute it subject to the privileges of the web
server user id." );
 script_set_attribute(attribute:"see_also", value:"http://exploitlabs.com/files/advisories/EXPL-A-2006-004-phpformgen.txt" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/30");
 script_cvs_date("$Date: 2012/09/05 23:37:10 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:musawir_ali:phpformgenerator");
script_end_attributes();

 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0, php: 1);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpformgenerator", "/phpform", "/forms", "/form", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the form exists.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it does...
  if (
    '<td align="right" class="small">opensource design' &&
    '<form action="fields.php"' >< res
  )
  {

    # Create a form with a file upload field.
    fname = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_");
    postdata = string(
      "FormName=", fname, "&",
      # nb: bogus email, needed to get by email validity check.
      "email=nessus@nessus.zzfo&",
      "redirect=&",
      "gen_thank=on&",
      "template_name=default&",
      "db=no&",
      "hostname=&",
      "dbuser=&",
      "dbpass=&",
      "dbname=&",
      "table_name=&",
      "tab_name=&",
      "column[0]=", SCRIPT_NAME, "&",
      "name[0]=", fname, "&",
      "type[0]=file_upload&",
      "size1[0]=&",
      "size2[0]=&",
      "required[0]=&",
      "active[0]=&",
      "hvalue[0]=&",
      "evalue[0]=",
      "fields=1"
    );
    r = http_send_recv3(method: "POST", item: dir + "/process3.php", port: port,
      content_type: "application/x-www-form-urlencoded",
      exit_on_fail: 1, data: postdata);
    res = r[2];

    # There's a problem if the form was created.
    #
    # nb: the app will email the actual location of the file to the
    #     address supplied when creating the form; alternatively, an 
    #     attacker could likely guess the filename from the server's
    #     Date response header -- the name is of the form 
    #     "hh_mm_ss_filename".
    if (string("reach it by clicking <a href='use/", fname, "/form1.html'>") >< res)
    {
      report = string(
        "\n",
        "Nessus created a file upload form on the remote host; please\n",
        "delete it as soon as possible :\n",
        "\n",
        "  ", dir, "/use/", fname, "/form1.html\n"
      );
      security_hole(port:port, extra:report);
      exit(0);
    }
  }
}
