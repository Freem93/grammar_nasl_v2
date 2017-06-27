#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76489);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2013-0169");
  script_bugtraq_id(57778);
  script_osvdb_id(89848);
  script_xref(name:"CERT", value:" 737740");

  script_name(english:"Ipswitch IMail Server 11.x / 12.x < 12.3 Information Disclosure");
  script_summary(english:"Checks versions of Ipswitch IMail services");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Ipswitch IMail Server 11.x or
12.x older than version 12.3 and is, therefore, affected by an
information disclosure vulnerability due to the included OpenSSL
version.

An error exists related to the SSL/TLS/DTLS protocols, CBC mode
encryption and response time. An attacker could obtain plaintext
contents of encrypted traffic via timing attacks.");
  # http://docs.ipswitch.com/_Messaging/IMailServer/v12.3/ReleaseNotes/index.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35da0f2d");
  script_set_attribute(attribute:"see_also", value:"http://www.imailserver.com/support/patches-upgrades/imail-v12-3/");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20130205.txt");

  script_set_attribute(attribute:"solution", value:"Upgrade to Ipswitch IMail Server version 12.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:imail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl","imap4_banner.nasl");
  script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");

ver = NULL;
service = NULL;
source  = NULL;

# - SMTP.
ports = get_kb_list("Services/smtp");
if (isnull(ports)) ports = make_list(25);
foreach port (ports)
{
  if (get_port_state(port) && !get_kb_item('SMTP/'+port+'/broken'))
  {
    banner = get_smtp_banner(port:port);
    # At least keep trying to find a banner
    if (isnull(banner) || strlen(banner) == 0) continue;

    if (" (IMail " >< banner)
    {
      pat = "^[0-9][0-9][0-9] .+ \(IMail ([0-9.]+) [0-9]+-[0-9]+\) NT-ESMTP Server";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            service = "SMTP";
            source  = match;
            break;
          }
        }
      }
      if (isnull(ver) && !thorough_tests) audit(AUDIT_SERVICE_VER_FAIL, "IMail SMTP", port);
    }
    else
      if (!thorough_tests) audit(AUDIT_NOT_LISTEN, "IMail SMTP", port);
  }
}

# - IMAP.
if (isnull(ver))
{
  ports = get_kb_list("Services/imap");
  if (isnull(ports)) ports = make_list(143);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      banner = get_imap_banner(port:port);
      # At least keep trying to find a banner
      if (isnull(banner) || strlen(banner) == 0) continue;

      if (" (IMail " >< banner)
      {
        pat = "IMAP4 Server[^(]+\(IMail ([0-9.]+) *([0-9]+-[0-9]+)?\)";
        matches = egrep(pattern:pat, string:banner);
        if (matches)
        {
          foreach match (split(matches, keep:FALSE))
          {
            item = eregmatch(pattern:pat, string:match);
            if (!isnull(item))
            {
              ver = item[1];
              service = "IMAP";
              source = match;
              break;
            }
          }
        }
        if (isnull(ver) && !thorough_tests) audit(AUDIT_SERVICE_VER_FAIL, "IMail IMAP", port);
      }
      else
        if (!thorough_tests) audit(AUDIT_NOT_LISTEN, "IMail IMAP", port);
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
      # At least keep trying to find a banner
      if (isnull(banner) || strlen(banner) == 0) continue;

      if (" (IMail " >< banner)
      {
        pat = "NT-POP3 Server .+ \(IMail ([0-9.]+) [0-9]+-[0-9]+\)";
        matches = egrep(pattern:pat, string:banner);
        if (matches)
        {
          foreach match (split(matches, keep:FALSE))
          {
            item = eregmatch(pattern:pat, string:match);
            if (!isnull(item))
            {
              ver = item[1];
              service = "POP3";
              source  = match;
              break;
            }
          }
        }
        if (isnull(ver) && !thorough_tests) audit(AUDIT_SERVICE_VER_FAIL, "IMail POP3", port);
      }
      else
        if (!thorough_tests) audit(AUDIT_NOT_LISTEN, "IMail POP3", port);
    }
  }
}

if (isnull(ver)) audit(AUDIT_SERVICE_VER_FAIL, "Ipswitch IMail Server", port);

# There's a problem if the version is < 12.3
if (
  ver =~ "^(11|12)\." &&
  ver_compare(ver:ver, fix:'12.3', strict:FALSE) < 0
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Service            : ' + service +
      '\n  Version source     : ' + source +
      '\n  Installed version  : ' + ver +
      '\n  Fixed version      : 12.3' +
      '\n';
   security_note(port:port,extra:report);
  }
  else security_note(port);

  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Ipswitch IMail Server", port, ver);
