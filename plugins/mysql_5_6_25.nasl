#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84767);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/24 14:57:04 $");

  script_cve_id(
    "CVE-2015-2582",
    "CVE-2015-2611",
    "CVE-2015-2617",
    "CVE-2015-2620",
    "CVE-2015-2639",
    "CVE-2015-2641",
    "CVE-2015-2643",
    "CVE-2015-2648",
    "CVE-2015-2661",
    "CVE-2015-4737",
    "CVE-2015-4752",
    "CVE-2015-4756",
    "CVE-2015-4757",
    "CVE-2015-4761",
    "CVE-2015-4767",
    "CVE-2015-4769",
    "CVE-2015-4771",
    "CVE-2015-4772");

  script_bugtraq_id(
    75751,
    75753,
    75759,
    75760,
    75762,
    75770,
    75774,
    75781,
    75785,
    75802,
    75813,
    75815,
    75822,
    75830,
    75835,
    75837,
    75844,
    75849
  );
  script_osvdb_id(
    124735,
    124736,
    124737,
    124738,
    124739,
    124740,
    124741,
    124742,
    124743,
    124744,
    124745,
    124746,
    124747,
    124748,
    124749,
    124750,
    124751,
    124752
  );

  script_name(english:"MySQL 5.5.x < 5.5.44 / 5.6.x < 5.6.25 Multiple Vulnerabilities (July 2015 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is version 5.5.x
prior to 5.5.44 or version 5.6.x prior to 5.6.25. It is, therefore,
potentially affected by the following vulnerabilities :

  - Multiple denial of service vulnerabilities exist in the
    following Server subcomponents which can be exploited by
    a remote, authenticated attacker :
    - Partition (CVE-2015-2617)
    - DML (CVE-2015-2648, CVE-2015-2611)
    - GIS (CVE-2015-2582)
    - I_S (CVE-2015-4752)
    - InnoDB (CVE-2015-4756)
    - Optimizer (CVE-2015-2643, CVE-2015-4757)
    - Partition (CVE-2015-4772)
    - Memcached (CVE-2015-4761)
    - RBR (CVE-2015-4771)
    - Security:Firewall (CVE-2015-4769, CVE-2015-4767)
    - Security:Privileges (CVE-2015-2641)

  - Multiple Information disclosure vulnerabilities exist in
    the following Server subcomponents which can be
    exploited by a remote, authenticated attacker to gain
    access to sensitive information :
    - Pluggable Auth (CVE-2015-4737)
    - Security:Privileges (CVE-2015-2620)

  - An unspecified vulnerability exists related to the
    Security:Firewall subcomponent of the Server that can be
    exploited by a remote, authenticated attacker to have an
    impact on the integrity of the system. (CVE-2015-2639)

  - A denial of service vulnerability exists in the Client
    subcomponent which can be exploited by a local attacker.
    No other details have been given. (CVE-2015-2661)");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18c2a85");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/15");

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

mysql_check_version(fixed:make_list('5.5.44', '5.6.25'), severity:SECURITY_WARNING);
