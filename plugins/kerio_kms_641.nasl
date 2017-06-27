#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25991);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/11 13:32:18 $");

  script_cve_id("CVE-2007-3993");
  script_bugtraq_id(25038);
  script_xref(name:"OSVDB", value:"38571");

  script_name(english:"Kerio MailServer < 6.4.1 Attachment Filter Unspecified Vulnerability");
  script_summary(english:"Checks version of KMS SMTP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by an unspecified vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Kerio MailServer, a commercial mail server
available for Windows, Linux, and Mac OS X platforms. 

According to its banner, the installed version of Kerio MailServer
contains an unspecified vulnerability involving the attachment filter." );
 script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/kms_history.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kerio MailServer 6.4.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/25");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:kerio_mailserver");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl", "imap4_banner.nasl", "doublecheck_std_services.nasl", "http_version.nasl");
  if ( NASL_LEVEL >= 3000 )
   script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/nntp", 119, "Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("misc_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");


# Try to get the version number from a banner.
ver = NULL;
service = NULL;
base_pat = " Kerio (Connect|MailServer) (([0-9][0-9.]+)( patch ([0-9]+))?) ";
#
# - SMTP.
if (isnull(ver))
{
  port = get_kb_item("Services/smtp");
  if (!port) port = 25;
  if (get_port_state(port))
  {
    banner = get_smtp_banner(port:port);
    pat = base_pat + "ESMTP ";
    matches = egrep(pattern:pat, string:banner);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          display_ver = item[2];
          ver = item[3];
          patch = item[5];
          service = "SMTP";
          break;
        }
      }
    }
    if (isnull(ver) && !thorough_tests) exit(0);
  }
}
# - POP3
if (isnull(ver))
{
  port = get_kb_item("Services/pop3");
  if (!port) port = 110;
  if (get_port_state(port))
  {
    banner = get_pop3_banner(port:port);
    pat = base_pat + "POP3";
    matches = egrep(pattern:pat, string:banner);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          display_ver = item[2];
          ver = item[3];
          patch = item[5];
          service = "POP3";
          break;
        }
      }
    }
    if (isnull(ver) && !thorough_tests) exit(0);
  }
}
# - NNTP.
if (isnull(ver))
{
  port = get_kb_item("Services/nntp");
  if (!port) port = 119;
  if (get_port_state(port))
  {
    banner = get_unknown_banner(port:port);
    pat = base_pat + "NNTP ";
    matches = egrep(pattern:pat, string:banner);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          display_ver = item[2];
          ver = item[3];
          patch = item[5];
          service = "NNTP";
          break;
        }
      }
    }
    if (isnull(ver) && !thorough_tests) exit(0);
  }
}
# - IMAP.
if (isnull(ver))
{
  port = get_kb_item("Services/imap");
  if (!port) port = 143;
  if (get_port_state(port))
  {
    banner = get_imap_banner(port:port);
    pat = base_pat + "IMAP";
    matches = egrep(pattern:pat, string:banner);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          display_ver = item[2];
          ver = item[3];
          patch = item[5];
          service = "IMAP";
          break;
        }
      }
    }
    if (isnull(ver) && !thorough_tests) exit(0);
  }
}


# There's a problem if the version is < 6.4.1.
if (ver)
{
  if (isnull(patch)) patch = 0;
  set_kb_item(name:'kerio/port', value:port);
  set_kb_item(name:'kerio/'+port+'/patch', value:patch);
  set_kb_item(name:'kerio/'+port+'/service', value:service);
  set_kb_item(name:'kerio/'+port+'/version', value:ver);
  set_kb_item(name:'kerio/'+port+'/display_version', value:display_ver);

  iver = split(ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(iver); i++)
    iver[i] = int(iver[i]);

  fix = split("6.4.1", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(iver); i++)
    if ((iver[i] < fix[i]))
    {
      report = string(
        "According to its ", service, " banner, the remote is running Kerio MailServer\n",
        "version ", display_ver, "."
      );
      security_hole(port:port, extra:report);

      exit(0);
      # never reached
    }
    else if (iver[i] > fix[i])
      break;

  exit(0, 'Kerio MailServer '+display_ver+' is not affected.');
}
