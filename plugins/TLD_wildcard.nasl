#
# (C) Tenable Network Security, Inc.
#
#
# Known top level domain wildcards, from 
# http://www.imperialviolet.org/dnsfix.html
#
# .COM and .NET	64.94.110.11 (and possibly others in AS30060)	
# .NU	64.55.105.9 212.181.91.6
# .TK	195.20.32.83 195.20.32.86
# .CC	206.253.214.102
# .MP	202.128.12.163
# .AC	194.205.62.122
# .CC	194.205.62.122 (206.253.214.102 also reported, but cannot confirm)
# .CX	219.88.106.80
# .MUSEUM	195.7.77.20
# .PH	203.119.4.6
# .SH	194.205.62.62
# .TM	194.205.62.42 (194.205.62.62 also reported, but cannot confirm)
# .WS	216.35.187.246
#
####
#
# I also found that:
# .PW	216.98.141.250 65.125.231.178
# .PW	69.20.61.189 (new redirection)
# .TD   146.101.245.154
# 
# .IO	194.205.62.102
# .TK	217.115.203.20	62.129.131.34
#       62.129.131.38 81.29.204.106 195.20.32.104 209.172.59.193 217.119.57.19
# .TD	www.nic.td.	62.23.61.4
# .MP	202.128.12.162 66.135.225.102 (new redirection?)
# .PW	 69.20.61.189  (new redirection?)
# .CX	203.119.12.43  (new redirection?)
# .NU   62.4.64.119 69.25.75.72 212.181.91.6
# .CD	64.94.29.64
# .PH	203.167.64.64	(new redirection)
# .SH	216.117.170.115 (new)
# .ST	195.178.186.40
# .TM	216.117.170.115 (new)
# .VG	64.94.29.14
# .WS	64.70.19.33 (new)


include("compat.inc");

if(description)
{
 script_id(11840);
 script_version ("$Revision: 1.17 $");

 script_name(english: "Exclude top-level domain wildcard hosts");
 script_summary(english: "Exclude some IPs from scan");

 script_set_attribute(
  attribute:"synopsis",
  value:"This plugin prevents scanning of top-level domain wildcard hosts."
 );
 script_set_attribute(attribute:"description", value:
"This host has an IP address known to be a wildcard record for a top-
level domain (TLD) or for a host within the 'nessus.org' domain.  It
has been blacklisted and will not be scanned." );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.icann.org/en/committees/security/sac015.htm"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Make sure that you entered the name / IP address correctly."
 );
 script_set_attribute(
  attribute:"risk_factor", 
  value:"None"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2003/09/18"
 );
 script_cvs_date("$Date: 2011/03/11 21:52:30 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_SETTINGS);

 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english: "Settings");
 exit(0);
}

#
excluded["64.94.110.11"] = 1;
excluded["64.55.105.9"] = 1;
excluded["212.181.91.6"] = 1;
excluded["195.20.32.83"] = 1;
excluded["195.20.32.86"] = 1;
excluded["206.253.214.102"] = 1;
excluded["202.128.12.163"] = 1;
excluded["194.205.62.122"] = 1;
excluded["219.88.106.80"] = 1;
excluded["195.7.77.20"] = 1;
excluded["203.119.4.6"] = 1;
excluded["194.205.62.62"] = 1;
excluded["194.205.62.42"] = 1;
excluded["216.35.187.246"] = 1;
#
excluded["216.98.141.250"] = 1;
excluded["65.125.231.178"] = 1;
excluded["146.101.245.154"] = 1;
#
excluded["194.205.62.102"] = 1;
excluded["202.128.12.162"] = 1;
excluded["217.115.203.20"] = 1;
excluded["62.129.131.34"]  = 1;
excluded["62.23.61.4"] = 1;
excluded["69.20.61.189"] = 1;
excluded["203.119.12.43"] = 1;
excluded["88.191.80.140"] = 1;
#
excluded["64.94.29.64"] = 1;
excluded["66.135.225.102"] = 1;
excluded["62.4.64.119"] = 1;
excluded["69.25.75.72"] = 1;
excluded["212.181.91.6"] = 1;
excluded["203.167.64.64"] = 1;
excluded["69.20.61.189"] = 1;
excluded["216.117.170.115"] = 1;
excluded["195.178.186.40"] = 1;
excluded["62.129.131.38"] = 1;
excluded["81.29.204.106"] = 1;
excluded["195.20.32.104"] = 1;
excluded["209.172.59.193"] = 1;
excluded["217.119.57.19"] = 1;
excluded["216.117.170.115"] = 1;
excluded["64.94.29.14"] = 1;
excluded["64.70.19.33"] = 1;
# MA 2008-05-09: the wildcards above are probably not used any more...
excluded["64.18.138.88"] = 1;	# CG
excluded["72.51.27.58"] = 1;	# CM
excluded["209.62.86.250"] = 1;	# CO.CM
excluded["202.30.50.101"] = 1;	# KR
excluded["213.146.149.143"] = 1;# LA
excluded["75.101.130.205"] = 1;	# MP
excluded["69.25.75.72"] = 1;	# NU
excluded["212.181.91.6"] = 1;	# NU
excluded["62.4.64.119"] = 1;	# NU
excluded["203.119.4.28"] = 1;	# PH
excluded["64.18.138.88"] = 1;	# RW
excluded["195.178.186.40"] = 1;	# ST
excluded["217.119.57.19"] = 1;	# TK
excluded["193.33.61.2"] = 1;	# TK
excluded["209.172.59.193"] = 1; # TK
excluded["217.115.151.98"] = 1; # TK
excluded["195.20.32.104"] = 1;	# TK
excluded["64.70.19.33"] = 1;	# WS

excluded["78.46.39.209"] = 1;	# CO.GP
excluded["211.234.122.23"] = 1;	# KR
excluded["222.231.8.226"] = 1;	# KR

target = get_host_ip();

if (excluded[target])
{
 ##display(target, " is in IP blacklist\n");
 set_kb_item(name: "Host/dead", value: TRUE);
 security_note(port: 0);
 exit(0);
}

exit(0);
# We do not test if Verisign "snubby mail rejector" is running on the
# machine, as it may be used elsewhere

soc = open_sock_tcp(25);
if (!soc) exit(0);
r = recv(socket: soc, length: 256);
if (r =~ '^220 +.*Snubby Mail Rejector')
{
  ##display(target, " looks like Verisign snubby mail server\n");
  set_kb_item(name: "Host/dead", value: TRUE);
  security_note(port: 0);
}

close(soc);
