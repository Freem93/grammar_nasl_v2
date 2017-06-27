#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22869);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2015/06/02 17:53:34 $");

  script_name(english:"Software Enumeration (SSH)");
  script_summary(english:"Displays the list of packages installed on the remote system.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to enumerate installed software on the remote host via
SSH.");
  script_set_attribute(attribute:"description", value:
"This plugin lists the software installed on the remote host by calling
the appropriate command, e.g. 'rpm -qa' on RPM-based Linux distributions,
qpkg, dpkg, etc.");
  script_set_attribute(attribute:"solution", value:
"Remove any software that is not in compliance with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/uname");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

function report(os, buf)
{
 local_var report;

 if (report_verbosity > 0)
 {
  if (buf =~ '[^ \t\r\n]') {
    report =
     '\n' + 'Here is the list of packages installed on the remote ' + os + ' system : ' +
     '\n' +
     '\n  ' + join(sort(split(buf)), sep:'  ');
  }
  else
  {
    report =
     '\n' + 'There are no packages installed on the remote ' + os + ' system.' +
     '\n';
  }
  security_note(port:0, extra:report);
 }
 else security_note(0);
 exit(0);
}

list = make_array(
  "Host/AIX/lslpp",                   "AIX",
  "Host/AmazonLinux/rpm-list",        "Amazon Linux AMI",
  "Host/CentOS/rpm-list",             "CentOS Linux",
  "Host/Debian/dpkg-l",               "Debian Linux",
  "Host/FreeBSD/pkg_info",            "FreeBSD",
  "Host/Gentoo/qpkg-list",            "Gentoo Linux",
  "Host/HP-UX/swlist",                "HP-UX",
  "Host/MacOSX/packages",             "Mac OS X",
  "Host/Mandrake/rpm-list",           "Mandriva Linux",
  "Host/McAfeeLinux/rpm-list",        "McAfee Linux",
  "Host/OracleVM/rpm-list",           "OracleVM",
  "Host/RedHat/rpm-list",             "Red Hat Linux",
  "Host/Slackware/packages",          "Slackware Linux",
  "Host/Solaris/showrev",             "Solaris",
  "Host/Solaris11/pkg-list",          "Solaris 11",
  "Host/SuSE/rpm-list",               "SuSE Linux",
  "Host/VMware/esxupdate",            "VMware ESXi / ESX",
  "Host/VMware/esxcli_software_vibs", "VMware ESXi / ESX",
  "Host/XenServer/rpm-list",          "Citrix XenServer",
  "Host/Junos_Space/rpm-list",        "Juniper Junos Space"
);

foreach item ( keys(list) )
{
 buf = get_kb_item(item);
 if ( buf ) report(os:list[item], buf:buf);
}
