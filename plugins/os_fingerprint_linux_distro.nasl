#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25335);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2017/03/13 21:17:23 $");

  script_name(english:"OS Identification : Linux Distribution");
  script_summary(english:"Determines the remote operating system.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system by looking at
certain files.");
  script_set_attribute(attribute:"description", value:
"This plugin attempts to identify the operating system type and version
by looking at certain files on the remote operating system (e.g.,
'/etc/redhat-release' on Red Hat).");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint_uname.nasl");
  script_require_keys("Host/OS/uname");

  exit(0);
}

kernel = get_kb_item("Host/OS/uname");
if ( ! kernel || "Linux Kernel" >!< kernel ) exit(0);

os = get_kb_item("Host/RedHat/release");
if ( ! os )
{
  os = get_kb_item("Host/AmazonLinux/release");
  if (os) os = "Amazon Linux AMI " + (os - "ALA");

}
if ( ! os )
{
  os = get_kb_item("Host/McAfeeLinux/release");
  if (os) os = "McAfee Linux OS " + (os - "MLOS");
}
if ( ! os ) os = get_kb_item("Host/CentOS/release");
if ("NSM" >< os) os = "Juniper NSM";
if ( ! os )
{
  os = get_kb_item("Host/etc/mandrake-release");
  if (os)
    os = ereg_replace(pattern:"(Mageia|Mandrake Linux|Mandrakelinux|Mandriva Linux|Mandriva Business Server) release ([0-9]+(\.[0-9])?).*", string:os, replace:"\1 \2");
}
if ( ! os ) {
	os = get_kb_item("Host/SuSE/release");
	if ( os )
	{
	  v = eregmatch(string: os, pattern: "(SUSE|SLE[SD])([0-9.]+)");
	  if (! isnull(v))
	  {
	    if (v[1] == 'SUSE') os = 'openSUSE ' + v[2];
	    else os = 'SuSE' + v[2];
	  }
	  else if ("SUSE" >< os)
	  {
	    os = str_replace(string: os, find:'SUSE', replace: 'SuSE');
	  }
	  if (os !~ 'SuSE[0-9]+\\.[0-9]')
	  {
	    pl = get_kb_item("Host/SuSE/patchlevel");
	    if (! isnull(pl)) os += "." + int(pl);
	  }
	}
}
if ( ! os )
	{
	  os = get_kb_item("Host/Gentoo/release");
	  if ( os && substr(os, 0, 6) != "Gentoo ") os = "Gentoo " + os;
	}
if ( ! os )
{
  os = get_kb_item("Host/Slackware/release");
  if (os =~ "^[0-9]") os = "Slackware " + os;
}
if ( ! os ) {
	os = get_kb_item("Host/Ubuntu/release");
	if ( os ) os = "Ubuntu " + os;
	}
if ( ! os ) {
	os = get_kb_item("Host/Debian/release");
	if ( os ) os = "Debian " + os;
	}
if ( ! os ) os = get_kb_item("Host/Junos_Space/release");

# Host/VMware/release=VMware ESX 4.0 (Kandinsky)\n
if(!os)
{
  os = get_kb_item("Host/VMware/release");
  if( os && "VMware ESX" >< os)
  {
    matches = eregmatch(pattern:"^VMware (ESXi? [0-9.]+).+",string:os);
    if (matches) os = "VMware " + matches[1];
  }
}

if(!os)
{
  os = get_kb_item("Host/EulerOS/release");
}
if (!os)
{
  os = get_kb_item("Host/Virtuozzo/release");
}

if ( os )
{
 os = chomp(os);
 set_kb_item(name:"Host/OS/LinuxDistribution", value:kernel +" on " + os);
 if("VMware ESX " >< os)
   set_kb_item(name:"Host/OS/LinuxDistribution/Type", value:"hypervisor");
 else
   set_kb_item(name:"Host/OS/LinuxDistribution/Type", value:"general-purpose");

 set_kb_item(name:"Host/OS/LinuxDistribution/Confidence", value:100);
}
