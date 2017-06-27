#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80191);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2013-3497");
  script_bugtraq_id(59760);
  script_osvdb_id(93112);

  script_name(english:"Juniper Junos Space < 12.3P2.8 Password Disclosure (JSA10567)");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a password disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos Space
version is prior to 12.3P2.8. It is, therefore, affected by a password
disclosure vulnerability. When an authenticated user is viewing
certain configuration pages in the interface, some passwords may be
displayed in plaintext.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10567");
  script_set_attribute(attribute:"solution", value:"Upgrade to Junos Space 12.3P2.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Junos_Space/version');

check_junos_space(ver:ver, fix:'12.3P2.8', severity:SECURITY_WARNING);
