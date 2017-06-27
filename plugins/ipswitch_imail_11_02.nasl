#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47743);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_bugtraq_id(41717,41718,41719);
  script_xref(name:"Secunia", value:"40638");

  script_name(english:"Ipswitch IMail Server < 11.02 Multiple Vulnerabilities");
  script_summary(english:"Checks versions of Ipswitch IMail services.");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Ipswitch IMail Server prior to
version 11.02. It is, therefore, affected by multiple issues :

  - By sending a specially crafted message to imailsrv.exe
    with multiple 'Reply-To' headers set, it may be 
    possible for a remote, unauthenticated attacker to 
    execute arbitrary code on the remote system. (ZDI-10-126)

  - By sending a specially crafted message containing '?Q?'
    operator, it may be possible for a remote, authenticated
    attacker to execute arbitrary code on the remote system
    with SYSTEM privileges. (ZDI-10-127)

  - By sending a specially crafted message with a overly 
    long '-NOTIFY' argument, it may be possible for a remote,
    unauthenticated attacker to execute arbitrary code on the
    remote system. (ZDI-10-128)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-126/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-127/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-128/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Jul/230");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Jul/231");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Jul/232");

  script_set_attribute(attribute:"solution", value:
"Upgrade to Ipswitch IMail Server version 11.02 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:   "2010/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:  "2010/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/07/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:imail");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl","imap4_banner.nasl");
  if ( NASL_LEVEL >= 3000 )
   script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143);

  exit(0);
}

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
    if (banner && " (IMail " >< banner)
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
     }
    if (isnull(ver) && !thorough_tests) exit(1, "NULL version from SMTP banner on port "+ port +".");
  }
}

# - IMAP.
if(isnull(ver))
{
  ports = get_kb_list("Services/imap");
  if (isnull(ports)) ports = make_list(143);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      banner = get_imap_banner(port:port);
      if (banner && " (IMail " >< banner)
      {
        pat = "IMAP4 Server \(IMail ([0-9.]+) *([0-9]+-[0-9]+)?\)";
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
      }
      if (isnull(ver) && !thorough_tests) exit(1, "NULL version from IMAP banner on port "+ port +".");
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
    if (banner && " (IMail " >< banner)
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
    }
    if (isnull(ver) && !thorough_tests) exit(1,"NULL version from POP3 banner on port "+ port + ".");
   }
  }
}

if(isnull(ver)) exit(1,"It was not possible to determine Ipswitch IMail Server version listening on port "+ port +".");

# There's a problem if the version is < 11.02
if (ver_compare(ver:ver, fix:'11.02') == -1)
{
  if(report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + ver +
             '\n  Fixed version      : 11.02' +
             '\n  Service            : ' + service +
             '\n  Version source     : ' + source+ '\n';
   security_hole(port:port,extra:report);
  }
  else security_hole(port) ;

  exit(0);
}
else
exit(0,"Ipswitch IMail Server version "+ ver + " is listening on port "+ port + " and hence is not vulnerable.");
