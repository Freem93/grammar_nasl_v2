#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80192);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2011-3368",
    "CVE-2011-4317",
    "CVE-2012-0053",
    "CVE-2013-5095",
    "CVE-2013-5096",
    "CVE-2013-5097"
  );
  script_bugtraq_id(
    49957,
    50802,
    51706,
    61791,
    61794,
    61795
  );
  script_osvdb_id(
    76079,
    77310,
    78556,
    96296,
    96300,
    96301
  );

  script_name(english:"Juniper Junos Space 11.1x < 13.1R1.6 Multiple Vulnerabilities (JSA10585)");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos Space
version is prior to 13.1R1.6. It is, therefore, affected by the
following vulnerabilities :

  - Multiple Vulnerabilities related to the included Apache
    HTTP server. (CVE-2011-3368, CVE-2011-4317,
    CVE-2012-0053)

  - A cross-site scripting flaw within the web interface
    that allows a remote attacker, with a specially crafted
    request, to access sensitive information.
    (CVE-2013-5095)

  - A flaw exists with the access control implementation
    that allows a remote attacker with read-only privileges
    to change the device's configuration. (CVE-2013-5096)

  - An information disclosure flaw exists that allows a
    remote attacker to obtain a list of users and their
    hashed passwords. (CVE-2013-5097)");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10585");
  script_set_attribute(attribute:"solution", value:"Upgrade to Junos Space 13.1R1.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/29");
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

check_junos_space(ver:ver, fix:'13.1R1.6', severity:SECURITY_WARNING, min:'11.1',  xss:TRUE);
