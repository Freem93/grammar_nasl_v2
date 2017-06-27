#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17778);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/11 19:30:34 $");

  script_cve_id("CVE-1999-1175");
  script_osvdb_id(6610);
  script_xref(name:"CISCO-BUG-ID", value:"CSCdk07174");

  script_name(english:"Cisco Web Cache Control Protocol Router Vulenrability");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Web Cache Control Protocol (WCCP), available on Cisco devices,
does not provide any authentication.  A router configured to support
Cache Engines will treat any host that sends it valid WCCP hello
packets as a cache engine, and may divert HTTP traffic to that host. 
If a router is configured to use WCCP, an attacker can divert web
traffic passing through such a router.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fdf32657");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-19980513-wccp-auth.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"1998/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"1998/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("cisco_func.inc");

version = get_kb_item_or_exit('Host/Cisco/IOS/Version');

# Affected: 12.0M
if (check_release(version:version, patched:make_list('12.0(0.8)M')))
{
  security_hole(port:0, extra:'\nUpdate to '+patch_update+' or later.\n');
  exit(0);
}

# Affected: 11.1CA
if (check_release(version:version, patched:make_list('11.1(19.1)CA')))
{
  security_hole(port:0, extra:'\nUpdate to '+patch_update+' or later.\n');
  exit(0);
}

# Affected: 11.1CC
if (check_release(version:version, patched:make_list('11.1(19.1)CC')))
{
  security_hole(port:0, extra:'\nUpdate to '+patch_update+' or later.\n');
  exit(0);
}

# Affected: 11.1CT
if (check_release(version:version, patched:make_list('11.1(19.1)CT')))
{
  security_hole(port:0, extra:'\nUpdate to '+patch_update+' or later.\n');
  exit(0);
}

# Affected: 11.2P
if (check_release(version:version, patched:make_list('11.2(14.2)P')))
{
  security_hole(port:0, extra:'\nUpdate to '+patch_update+' or later.\n');
  exit(0);
}

exit(0, "The host is not affected.");
