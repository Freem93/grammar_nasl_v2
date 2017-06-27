#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25711);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-3796");
  script_bugtraq_id(24936);
  script_osvdb_id(38182);

  script_name(english:"MailMarshal Spam Quarantine Interface Arbitrary Account Password Retrieval");
  script_summary(english:"Checks version in SMTP banner");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET script that is susceptible
to an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Spam Quarantine Management web
component of MailMarshal SMTP, a mail server for Windows. 

The version of the Spam Quarantine Management web component installed
on the remote host fails to sanitize input to the 'emailTextBox'
parameter of the 'Register.aspx' script before using it in database
queries.  By appending a long string of blanks and his own email
address, an unauthenticated attacker may be able to leverage this
issue to reset and retrieve the password to any user account provided
he knows the email address associated with it." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Jul/323" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MailMarshal SMTP 6.2.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/18");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "doublecheck_std_services.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/smtp", 25, "Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("smtp_func.inc");


# Grab the version from the SMTP banner.
port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0, "Port "+port+" is closed");

ver = NULL;
banner = get_smtp_banner(port:port);
if (! banner)
 exit(1, "No SMTP banner on port "+port+".");
if (" ESMTP MailMarshal " >!< banner)
 exit(0, "MailMarshal is not running on port "+port+".");

  pat = " ESMTP MailMarshal \(v([0-9][0-9.]+)\)";
  matches = egrep(pattern:pat, string:banner);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        ver = item[1];
        break;
      }
    }
  }



# If it's a vulnerable version...
if (! ver)
 exit(1, "MailMarshall version could not be identified on port "+port+".");
if (ver !~ "^([0-5]\.|6\.([01]\.|2\.0[^0-9]?))")
 exit(0, "MailMarshall is not vulnerable on port "+port+".");

  report = NULL;

  # If we're being paranoid, just flag it as vulnerable.
  if (report_paranoia > 1)
    report = string(
      "\n",
      "According to its SMTP banner, version ", ver, " of MailMarshal is\n",
      "installed on the remote host, but Nessus did not check whether the\n",
      "optional Spam Quarantine component is available because of the Report\n",
      "Paranoia setting in effect when this scan was run.\n"
    );
  # Otherwise, make sure the affected component is installed.
  else 
  {
    port = get_http_port(default:80, embedded: 0, asp: 1);

    # Loop through directories.
    if (thorough_tests) dirs = list_uniq(make_list("/SpamConsole", cgi_dirs()));
    else dirs = make_list(cgi_dirs());

    foreach dir (dirs)
    {
      url = string(dir, "/Register.aspx");
      w = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);
      res = w[2];

      # If it is...
      if (
        "MailMarshal" >< res && 
        "Spam Quarantine Management" >< res &&
        '<form name="Form1" method="post" action="Register.aspx"' >< res
      )
      {
        report = string(
          "\n",
          "According to its SMTP banner, version ", ver, " of MailMarshal is\n",
          "installed on the remote host and the affected component is accessible\n",
          "under the directory '", dir, "'."
        );
        break;
      }
    }
  }

if (report)
 security_hole(port:port, extra:report);
else
 exit(0, "No vulnerable MailMarshal instance was found on port "+port+".");

