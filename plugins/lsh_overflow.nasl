#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: Haggis <haggis@learningshophull.co.uk>
# To: bugtraq@securityfocus.com
# Subject: Remote root vuln in lsh 1.4.x
# Date: Fri, 19 Sep 2003 13:01:24 +0000
# Message-Id: <200309191301.24607.haggis@haggis.kicks-ass.net>

include("compat.inc");

if (description)
{
 script_id(11843);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");

 script_cve_id("CVE-2003-0826");
 script_bugtraq_id(8655);
 script_osvdb_id(11744);
 script_xref(name:"EDB-ID", value:"23161");
 script_xref(name:"EDB-ID", value:"23162");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:041");

 script_name(english:"LSH Daemon < 1.4.3 / 1.5.3 lshd Remote Overflow");
 script_summary(english:"Checks for the remote SSH version");

 script_set_attribute(attribute:"synopsis", value:"The remote SSH server is affected by a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of LSH (a free replacement for
SSH) is a version prior to 1.4.3 / 1.5.3.  It is, therefore, affected by
a buffer overflow vulnerability due to improper handling of user input
to the 'read_line.c', 'channel_commands.c', and 'client_keyexchange.c'
source files that could allow an attacker to execute arbitrary code or
cause a denial of service.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Sep/298");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Sep/314" );
 script_set_attribute(attribute:"solution", value:"Upgrade to LSH 1.4.3 / 1.5.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/20");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/09/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/09/19");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:lsh");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencies("ssh_detect.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Ensure the port is open.
port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

if(egrep(pattern:"lshd[-_](0\.|1\.[0-3]\.|1\.4\.[0-2]([^0-9]|$)|1\.5\.[0-2]([^0-9]|$))", string:banner, icase:TRUE)) security_hole(port);
