#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91890);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/01 20:11:58 $");

  script_cve_id("CVE-2016-1265");
  script_osvdb_id(137062, 137064, 137065, 137066);
  script_xref(name:"JSA", value:"JSA10727");

  script_name(english:"Juniper Junos Space < 15.1R3 Multiple Vulnerabilities (JSA10727)");
  script_summary(english:"Checks the version of Junos Space.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Junos
Space running on the remote device is prior to 15.1R3. It is,
therefore, affected by multiple unspecified vulnerabilities, including
cross-site request forgery (XSRF), default authentication credentials,
information disclosure, and command injection. An unauthenticated,
remote attacker can exploit these to execute arbitrary code or gain
access to devices managed by Junos Space.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10727&actp=search
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a84b985b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Junos Space version 15.1R3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Junos_Space/version');

check_junos_space(ver:ver, fix:'15.1R3', severity:SECURITY_HOLE, xsrf:TRUE);
