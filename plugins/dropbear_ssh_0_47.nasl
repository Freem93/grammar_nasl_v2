#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34769);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2005-4178");
 script_bugtraq_id(15923);
 script_osvdb_id(21847);
 
 script_name(english:"Dropbear SSH Server svr_ses.childpidsize Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Authenticated users can gain elevated privileges." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is runnning a version of
Dropbear SSH before 0.47.  Such versions contain a buffer allocation
error that may allow an authenticated user to gain elevated
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://lists.ucc.gu.uwa.edu.au/pipermail/dropbear/2005q4/000312.html" );
 script_set_attribute(attribute:"see_also", value:"http://matt.ucc.asn.au/dropbear/CHANGES" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the Dropbear SSH 0.47 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/11");
 script_cvs_date("$Date: 2016/10/17 13:39:45 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:matt_johnston:dropbear_ssh_server");
script_end_attributes();

 script_summary(english: "Checks remote SSH server type and version");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_require_ports("Services/ssh", 22);
 script_dependencies("ssh_detect.nasl");
 exit(0);
}

#
include("backport.inc");
port = get_kb_item("Services/ssh");
if (!port) port = 22;
if (!get_port_state(port)) exit(0);

banner = get_kb_item("SSH/banner/" + port );
if (! banner) exit(0);

banner = tolower(get_backport_banner(banner:banner));

if("dropbear" >< banner)
{
    if (ereg(pattern:"ssh-.*-dropbear_0\.(([0-3].*)|4[0-6]($|[^0-9]))", string:banner))
    {
        security_hole(port);
    }
}
