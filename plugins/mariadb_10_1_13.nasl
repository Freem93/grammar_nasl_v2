#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93739);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_osvdb_id(
    136367,
    136368,
    136369,
    136371,
    136372,
    136373,
    136375
  );

  script_name(english:"MariaDB 10.1.x < 10.1.13 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.1.x prior to
10.1.13. It is, therefore, affected by multiple vulnerabilities :

  - An overflow condition exists in the
    extension_based_table_discovery() function in
    discover.cc due to improper validation of user-supplied
    input. An authenticated, remote attacker can exploit
    this to cause a denial of service condition or the
    execution of arbitrary code. (VulnDB 136367)

  - A flaw exists in the Item::basic_const_item() function
    that is triggered when handling nested NULLIF
    statements. An authenticated, remote attacker can
    exploit this to crash the database, resulting in a
    denial of service condition. (VulnDB 136368)

  - A flaw exists in the Item::cache_const_expr_analyzer()
    function in item.cc that is triggered during the
    handling of caches. An authenticated, remote attacker
    can exploit this to crash the database, resulting in a
    denial of service condition. (VulnDB 136369)

  - A flaw exists in the
    Item_sum_field::get_tmp_table_field() function in
    item_sum.h that is triggered during the handling of
    temporary tables. An authenticated, remote attacker can
    exploit this to crash the database, resulting in a
    denial of service condition. (VulnDB 136371)

  - A flaw exists that is triggered during the handling of a
    specially crafted QT_ITEM_FUNC_NULLIF_TO_CASE NULLIF
    statement. An authenticated, remote attacker can exploit
    this to crash the database, resulting in a denial of
    service condition. (VulnDB 136372)

  - A flaw exists in the Item::save_in_field() function that
    is triggered during the handling of date values. An
    authenticated, remote attacker can exploit this to crash
    the database, resulting in a denial of service
    condition. (VulnDB 136373)

  - A flaw exists in the mariadb_dyncol_unpack() function in
    ma_dyncol.c due to improper validation of user-supplied
    input. An authenticated, remote attacker can exploit
    this to corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code.
    (VulnDB 136375)");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.org/mariadb-10-1-13-connectorj-1-3-7-now-available/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-10113-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10113-release-notes/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'10.1.13-MariaDB', min:'10.1', severity:SECURITY_HOLE);
