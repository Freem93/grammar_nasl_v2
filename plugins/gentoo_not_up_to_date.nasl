#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34312);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/01/25 01:19:08 $");
  script_name(english: "Gentoo is not up-to-date");
  script_summary(english: "Check timestamp of Gentoo portage tree");

 script_set_attribute(attribute:"synopsis", value:
"The remote Gentoo Linux host is not up-to-date." );
 script_set_attribute(attribute:"description", value:
"According to its timestamp, the portage tree on the remote Gentoo
system has not been updated for at least two years.  This almost
certainly means that security updates are missing and that it is
affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://www.gentoo.org/doc/en/gentoo-upgrading.xml" );
 script_set_attribute(attribute:"solution", value:
"Update your system. For example :

  # emerge --sync
  # emerge -u system -v --newuse
  # etc-update; env-update; source /etc/profile
  # emerge -u world -D -v --newuse
  # etc-update; env-update; source /etc/profile" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/29");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english: "Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
  script_dependencie("ssh_get_info.nasl");
  script_require_keys("Host/Gentoo/release", "Host/Gentoo/emerge_info");
  exit(0);
}

#

info = get_kb_item("Host/Gentoo/emerge_info");
timestamp = NULL;
# Timestamp of tree: Mon, 22 Sep 2008 08:07:24 +0000
if (! info)
 v = NULL;
else
 v = eregmatch(string: info, 
    pattern: '[\r\n]Timestamp of tree:[ \t]+([A-Z][a-z][a-z],[ \t]+[0-3][0-9][ \t]+([A-Z][a-z][a-z])[ \t]+(199[0-9]|20[0-3][0-9]) [^\r\n]*)[\r\n]');
if (! isnull(v))
{
 year = int(v[3]); 
 month = v[2];
 date = v[1];

 i = 31;
 monthval['Jan'] = i; i += 28;
 monthval['Feb'] = i; i += 31;
 monthval['mar'] = i; i += 30;
 monthval['Apr'] = i; i += 31;
 monthval['May'] = i; i += 30;
 monthval['Jun'] = i; i += 31;
 monthval['Jul'] = i; i += 31;
 monthval['Aug'] = i; i += 30;
 monthval['Sep'] = i; i += 31;
 monthval['Oct'] = i; i += 30;
 monthval['Nov'] = i; i += 31;
 monthval['Dev'] = i; 

 # approximative value
 days = 365 * (year - 1970) + 
      (year / 4) - 492 +	# leap years
      (365 - monthval[month]);
 timestamp = days * 86400;
}
else
{
 buf = get_kb_item("Host/Gentoo/timestamp_x");
 if (buf)
 {
  v = eregmatch(string: chomp(buf),  
    pattern: '^([1-9][0-9]+)[ \t]+([A-Z][a-z][a-z] .* (199[0-9]|20[01][0-9]) .*)');
  if (! isnull(v))
  {
    timestamp = int(v[1]);
    year = int(v[3]); 
    date = v[2];  
  }
 }

 if (! timestamp)
 {
  buf = get_kb_item("Host/Gentoo/timestamp");
  if (buf)
  {
    date = chomp(buf);
    v = eregmatch(string: date,
      pattern: '^[A-Z][a-z][a-z] .*[ \t](199[0-9]|20[01][0-9])[ \t]*$');
    if (! isnull(v))
      year = int(v[1]); 
  }
  if (! year) exit(0);
 }
}


if (unixtime() - timestamp > 63072000)	# Two years
  security_hole(port: 0, extra:
strcat('\nThis system was last updated on ', date, '.\n'));
