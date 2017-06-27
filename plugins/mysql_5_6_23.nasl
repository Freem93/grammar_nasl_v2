#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82799);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/19 04:39:47 $");

  script_cve_id(
    "CVE-2014-3569",
    "CVE-2015-0405",
    "CVE-2015-0423",
    "CVE-2015-0433",
    "CVE-2015-0438",
    "CVE-2015-0439",
    "CVE-2015-0441",
    "CVE-2015-2566",
    "CVE-2015-2568",
    "CVE-2015-2573"
  );
  script_bugtraq_id(
    71934,
    74073,
    74078,
    74085,
    74089,
    74091,
    74098,
    74103,
    74110,
    74126
  );
  script_osvdb_id(
    116423,
    120722,
    120724,
    120726,
    120727,
    120729,
    120731,
    120732,
    120738,
    120742
  );

  script_name(english:"MySQL 5.5.x < 5.5.42 / 5.6.x < 5.6.23 Multiple DoS Vulnerabilities (April 2015 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is version 5.5.x
prior to 5.5.42 or version 5.6.x prior to 5.6.23. It is, therefore,
potentially affected by multiple denial of service vulnerabilities :

  - A NULL pointer dereference flaw exists when the SSLv3
    option isn't enabled and an SSLv3 ClientHello is
    received. This allows a remote attacker, using an
    unexpected handshake, to crash the daemon, resulting in
    a denial of service. (CVE-2014-3569)

  - Additionally, there are unspecified flaws in the
    following MySQL subcomponents that allow a denial of
    service by an authenticated, remote attacker :

    - XA (CVE-2015-0405)
    - Optimizer (CVE-2015-0423)
    - InnoDB : DML (CVE-2015-0433)
    - Partition (CVE-2015-0438)
    - InnoDB (CVE-2015-0439)
    - Security : Encryption (CVE-2015-0441)
    - DML (CVE-2015-2566)
    - Security : Privileges (CVE-2015-2568)
    - DDL (CVE-2015-2573)");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4f2e20f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.42 / 5.6.23 or later as referenced in the
Oracle April 2015 Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");
mysql_check_version(fixed:make_list('5.5.42', '5.6.23'), severity:SECURITY_WARNING);
