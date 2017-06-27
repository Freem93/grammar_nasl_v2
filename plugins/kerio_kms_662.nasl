#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35258);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/11 13:32:18 $");

  script_cve_id("CVE-2008-5760", "CVE-2008-5769");
  script_bugtraq_id(32863);
  script_xref(name:"Secunia", value:"32955");
  script_osvdb_id(50788, 50789, 50790);

  script_name(english:"Kerio MailServer < 6.6.2 Multiple XSS (KSEC-2008-12-16-01)");
  script_summary(english:"Checks for Kerio MailServer < 6.6.2");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by several cross-site scripting
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of Kerio
MailServer prior to 6.6.2.  Multiple files in such versions are
reportedly affected by cross-site scripting vulnerabilities. 

  - The application fails to sanitize input to the parameter
    'folder' of the 'mailCompose.php' script as well as the 
    parameter 'daytime' of the 'calendarEdit.php' script
    before using it to generate dynamic HTML.

  - Content passed to 'sent' parameter of the 'error413.php'
    script is not sanitized before being returned to the 
    user.

Successful exploitation of these issues could lead to execution of
arbitrary HTML and script code in a user's browser within the security
context of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/security_advisory.html#0812" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kerio MailServer 6.6.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/12/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:kerio_mailserver");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("kerio_kms_641.nasl");
  script_require_keys("kerio/port");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item('kerio/port');
if (isnull(port)) exit(1, "The 'kerio/port' KB item is missing.");

service = get_kb_item('kerio/'+port+'/service');
ver = get_kb_item('kerio/'+port+'/version');
display_ver = get_kb_item('kerio/'+port+'/display_version');

# There's a problem if the version is < 6.6.2
iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

fix = split("6.6.2", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(iver); i++)
  if ((iver[i] < fix[i]))
  {
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	
    if (report_verbosity)
    {
      report = string(
        "\n",
        "According to its ", service, " banner, the remote host is running Kerio\n",
        "MailServer version ", display_ver, ".\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
    # never reached
  }
  else if (iver[i] > fix[i])
    break;

exit(0, 'Kerio MailServer '+display_ver+' is not affected.');
