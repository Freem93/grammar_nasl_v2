#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:038
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13806);
 script_version ("$Revision: 1.10 $");
 script_cvs_date("$Date: 2011/11/03 18:08:43 $");
 
 name["english"] = "SUSE-SA:2003:038: openssh";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:038 (openssh).


The openssh package is the most widely used implementation of the secure
shell protocol family (ssh). It provides a set of network connectivity
tools for remote (shell) login, designed to substitute the traditional
BSD-style r-protocols (rsh, rlogin). openssh has various authentification
mechanisms and many other features such as TCP connection and X11 display
forwarding over the fully encrypted network connection as well as file
transfer facilities.

A programming error has been found in code responsible for buffer
management. If exploited by a (remote) attacker, the error may lead to
unauthorized access to the system, allowing the execution of arbitrary
commands.
The error is known as the buffer_append_space()-bug and is assigned the
Common Vulnerabilities and Exposures (CVE) name CVE-2003-0693.

At the time of writing this announcement, it is unclear if the
buffer_append_space()-bug is exploitable. However, an increasing amount
of TCP connection attempts to port 22 (the ssh default port) has been
observed in the internet during the past days, which may indicate that
there exists an exploit for the error.

Please note that we have disabled the Privilege Separation feature in
the ssh daemon (sshd) with this update. The PrivSep feature is designed
to have parts of the ssh daemon's work running under lowered privileges,
thereby limiting the effect of a possible vulnerability in the code. The
PrivSep feature is turned on/off by the UsePrivilegeSeparation keyword
in sshd's configuration file /etc/ssh/sshd_config. The feature is held
responsible for malfunctions in PAM (Pluggable Authentification Modules).
The update mechanism will not overwrite configuration files that have
been altered after the package installation." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_038_openssh.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the openssh package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openssh-2.9.9p2-155", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-2.9.9p2-155", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.4p1-214", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.4p1-214", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.5p1-106", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
