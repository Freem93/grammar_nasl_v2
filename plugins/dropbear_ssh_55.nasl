#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58183);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2012-0920");
  script_bugtraq_id(52159);
  script_osvdb_id(79590);

  script_name(english:"Dropbear SSH Server Channel Concurrency Use-after-free Remote Code Execution");
  script_summary(english:"Checks remote SSH server type and version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is affected by a remote code execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported banner, the remote host is running a
version of Dropbear SSH before 2012.55.  As such, it reportedly
contains a flaw that might allow an attacker to run arbitrary code on
the remote host with root privileges if they are authenticated using a
public key and command restriction is enforced. 

Note that Nessus has not tried to exploit this vulnerability but
instead has relied solely on the version in the service's banner. 

Note also, in cases where the host is running ESXi 4.0 or ESXi 4.1,
VMware states in their KB article id 2037316 that this is a false
positive since administrative access is required to login via SSH so
there are no privileges to be gained by exploiting this issue.  That
is true only in a default setup, not one in which SSH access has been
enabled for non-root users."
  );
  script_set_attribute(attribute:"see_also", value:"https://matt.ucc.asn.au/dropbear/CHANGES");
  script_set_attribute(attribute:"see_also", value:"https://secure.ucc.asn.au/hg/dropbear/rev/818108bf7749");
  script_set_attribute(attribute:"see_also", value:"https://www.mantor.org/~northox/misc/CVE-2012-0920.html");
  # https://kb.vmware.com/selfservice/microsites/search.do?cmd=displayKC&externalId=2037316
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2ca47ea");
  script_set_attribute(attribute:"solution", value:"Upgrade to the Dropbear SSH 2012.55 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:matt_johnston:dropbear_ssh_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"ssh", exit_on_fail:TRUE);

orig_banner = get_kb_item_or_exit("SSH/banner/" + port);
banner = get_backport_banner(banner:orig_banner);

# Make sure it's Dropbear.
if ("dropbear" >!< banner) exit(0, "The SSH service on port "+port+" is not Dropbear.");
if (backported) exit(1, "The banner from the Dropbear server on port "+port+" indicates patches may have been backported.");


item = eregmatch(pattern:"dropbear_([0-9\.]+)", string:banner);
if (isnull(item)) exit(1, 'Failed to parse the banner from the SSH server listening on port ' + port + '.');
version = item[1];

#SSH version : SSH-2.0-dropbear_0.53.1
#SSH version : SSH-2.0-dropbear_2011.54
if ( 
  version =~ "0\.5[2-4]($|[^0-9])" ||
  version =~ "20(0[0-9]|1[02])\.5[2-4]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + orig_banner +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 2012.55\n';
    security_hole(port:port, extra:report); 
  } 
  else security_hole(port:port);
  exit(0);
}
else exit(0, "The Dropbear "+version+" server listening on port "+port+" is unaffected.");
