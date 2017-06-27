#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78477);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id(
    "CVE-2014-6464",
    "CVE-2014-6469",
    "CVE-2014-6491",
    "CVE-2014-6494",
    "CVE-2014-6496",
    "CVE-2014-6500",
    "CVE-2014-6507",
    "CVE-2014-6555",
    "CVE-2014-6559"
  );
  script_bugtraq_id(
    70444,
    70446,
    70451,
    70469,
    70478,
    70487,
    70497,
    70530,
    70550
  );
  script_osvdb_id(
    113252,
    113253,
    113254,
    113255,
    113257,
    113259,
    113260,
    113261,
    113267
  );

  script_name(english:"MySQL 5.5.x < 5.5.40 / 5.6.x < 5.6.21 Multiple Vulnerabilities (October 2014 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is version 5.5.x
prior to 5.5.40 or 5.6.x prior to 5.6.21. It is, therefore, affected
by errors in the following components :

  - C API SSL CERTIFICATE HANDLING
  - CLIENT:SSL:yaSSL
  - SERVER:DML
  - SERVER:INNODB DML FOREIGN KEYS
  - SERVER:OPTIMIZER
  - SERVER:SSL:yaSSL");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1b27c77");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.40 / 5.6.21 or later as referenced in the
Oracle October 2014 Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  # CVE-2014-6507

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("mysql_version.inc");
mysql_check_version(fixed:make_list('5.5.40', '5.6.21'), severity:SECURITY_HOLE);
