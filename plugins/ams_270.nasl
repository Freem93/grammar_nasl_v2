#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41644);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2009-3445");
  script_bugtraq_id(36519);
  script_osvdb_id(58332);
  script_xref(name:"Secunia", value:"36888");

  script_name(english:"Ability Mail Server < 2.70 IMAP4 FETCH DoS");
  script_summary(english:"Checks versions of AMS services");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a denial of service
vulnerability.");

  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Ability Mail Server. 

According to its banner, the IMAP service component of the installed
version of Ability Mail Server fails to correctly parse FETCH
commands.  By sending a specially crafted FETCH command, an attacker
may be able to exploit this vulnerability to crash the IMAP server.");

  script_set_attribute(attribute:"see_also", value:"http://www.code-crafters.com/abilitymailserver/updatelog.html" );

  script_set_attribute(attribute:"solution", value:
"Upgrade to Ability Mail Server version 2.70 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/28");

 script_cvs_date("$Date: 2016/05/04 14:21:28 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl", "http_version.nasl");
  if ( NASL_LEVEL >= 3000 )
   script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143, "Services/www", 8000, 9000);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");


# Try to get the version number from IMAP banner.

ver = NULL;
service = NULL;

# - IMAP.

ports = get_kb_list("Services/imap");
if (isnull(ports)) ports = make_list(143);
foreach port (ports)
{
  if (get_port_state(port))
  {
    banner = get_imap_banner(port:port);
    if (banner && " Code-Crafters Ability Mail Server " >< banner)
    {
      pat = ", with Code-Crafters Ability Mail Server ([0-9][0-9.]+)\.";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match[0]);
          if (!isnull(item))
          {
            ver = item[1];
            service = "IMAP";
            break;
          }
        }
      }
    }
  }
}

if(report_paranoia > 1)
{
# - SMTP.
if (isnull(ver))
{
  ports = get_kb_list("Services/smtp");
  if (isnull(ports)) ports = make_list(25);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      banner = get_smtp_banner(port:port);
      if (banner && "Code-Crafters Ability Mail Server" >< banner)
      {
        pat = " ESMTP \(Code-Crafters Ability Mail Server ([0-9][0-9.]+)\)";
        matches = egrep(pattern:pat, string:banner);
        if (matches)
        {
          foreach match (split(matches, keep:FALSE))
          {
            item = eregmatch(pattern:pat, string:match[0]);
            if (!isnull(item))
            {
              ver = item[1];
              service = "SMTP";
              break;
           }
         }
       }
     }
    if (isnull(ver) && !thorough_tests) exit(1, "NULL version from SMTP banner.");
  }
 }
}

# - POP3
if (isnull(ver))
{
  ports = get_kb_list("Services/pop3");
  if (isnull(ports)) ports = make_list(110);
  foreach port (ports)
  {
  if (get_port_state(port))
  {
    banner = get_pop3_banner(port:port);
    if (banner && " Code-Crafters Ability Mail Server" >< banner)
    {
      pat = "with Code-Crafters Ability Mail Server ([0-9][0-9.]+) <";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match[0]);
          if (!isnull(item))
          {
            ver = item[1];
            service = "POP3";
            break;
          }
        }
      }
    }
    if (isnull(ver) && !thorough_tests) exit(1,"NULL version from POP3 banner.");
   }
  }
}

# - Web servers.
if (isnull(ver))
{
  ports = get_kb_list("Services/www");
  if (isnull(ports)) ports = make_list(8000);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      # nb: get_http_banner() doesn't work on the webmail port.
      if (port == 8000)
      {
        banner = "";
	r = http_send_recv3(method:"GET", item:"/_index", port:port);
        banner = strcat(r[0], r[1]);
      }
      else banner = get_http_banner(port:port);
      if (banner && " Code-Crafters Ability Mail Server " >< banner)
      {
        pat = "^Server: Code-Crafters Ability Mail Server ([0-9][0-9.]+)";
        matches = egrep(pattern:pat, string:banner);
        if (matches)
        {
          foreach match (split(matches, keep:FALSE))
          {
            item = eregmatch(pattern:pat, string:match[0]);
            if (!isnull(item))
            {
              ver = item[1];
              service = "HTTP (port " + port + ")";
              break;
            }
          }
        }
      }
       if (isnull(ver) && !thorough_tests) exit(1,"NULL version from HTTP banner.");
     }
   }
 }

}

# There's a problem if the version is < 2.70.
if (ver)
{
  iver = split(ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(iver); i++)
    iver[i] = int(iver[i]);

  fix = split("2.70", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(iver); i++)
    if ((iver[i] < fix[i]))
    {
      report = string(
        "\n",
        "According to its ", service, " banner, the remote is running Ability Mail\n",
        "Server version ", ver, "."
      );
      if("IMAP" >!< service)
        report += string(
          "\n",
          "\n",
          "Note that Nessus flagged the remote version as vulnerable based on\n",
          "a banner from a non-IMAP based service because of the\n", 
          "'report_paranoia' setting in affect during the scan."
        );
      security_warning(port:port, extra:report);

      exit(0);
    }
    else if (iver[i] > fix[i])
    { 
      break;
      exit(0, "The installed version of Ability Mail Server is not vulnerable.");
    }
}  
