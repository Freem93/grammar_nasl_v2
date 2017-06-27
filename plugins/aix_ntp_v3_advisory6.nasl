#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92356);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id(
    "CVE-2015-7973",
    "CVE-2015-7977",
    "CVE-2015-7979",
    "CVE-2015-8139",
    "CVE-2015-8140",
    "CVE-2015-8158"
  );
  script_bugtraq_id(
    81814,
    81815,
    81816,
    81963,
    82102,
    82105
  );
  script_osvdb_id(
    133378,
    133382,
    133388,
    133389,
    133390,
    133391,
    133414
  );
  script_xref(name:"CERT", value:"718152");

  script_name(english:"AIX NTP v3 Advisory : ntp_advisory6.asc (IV83984) (IV83993) (IV83994) (IV83995) (IV84269)");
  script_summary(english:"Checks the version of the ntp packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of NTP installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of NTP installed on the remote AIX host is affected by
the following vulnerabilities :

  - A flaw exists in the receive() function due to the use
    of authenticated broadcast mode. A man-in-the-middle
    attacker can exploit this to conduct a replay attack.
    (CVE-2015-7973)

  - A NULL pointer dereference flaw exists in ntp_request.c
    that is triggered when handling ntpdc relist commands.
    A remote attacker can exploit this, via a specially
    crafted request, to crash the service, resulting in a
    denial of service condition. (CVE-2015-7977)

  - An unspecified flaw exists in authenticated broadcast
    mode. A remote attacker can exploit this, via specially
    crafted packets, to cause a denial of service condition.
    (CVE-2015-7979)

  - A flaw exists in ntpq and ntpdc that allows a remote
    attacker to disclose sensitive information in
    timestamps. (CVE-2015-8139)

  - A flaw exists in the ntpq protocol that is triggered
    during the handling of an improper sequence of numbers.
    A man-in-the-middle attacker can exploit this to conduct
    a replay attack. (CVE-2015-8140)

  - A flaw exists in the ntpq client that is triggered when
    handling packets that cause a loop in the getresponse()
    function. A remote attacker can exploit this to cause an
    infinite loop, resulting in a denial of service
    condition. (CVE-2015-8158)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/ntp_advisory6.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevel = oslevel - "AIX-";

oslevelcomplete = chomp(get_kb_item("Host/AIX/oslevelsp"));
if (isnull(oslevelcomplete)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevelparts = split(oslevelcomplete, sep:'-', keep:0);
if ( max_index(oslevelparts) != 4 ) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
ml = oslevelparts[1];
sp = oslevelparts[2];

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

aix_ntp_vulns = {
  "5.3": {
    "12": {
      "09": {
        "bos.net.tcp.client": {
          "minfilesetver":"5.3.12.0",
          "maxfilesetver":"5.3.12.10",
          "patch":"(IV84269m9a)"
        }
      }
    }
  },
  "6.1": {
    "09": {
      "04": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.102",
          "patch":"(IV83984m4a)"
        }
      },
      "05": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.102",
          "patch":"(IV83984m5a)"
        }
      },
      "06": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.102",
          "patch":"(IV83984m6a)"
        }
      },
      "07": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.102",
          "patch":"(IV83984s7a)"
        }
      }
    }
  },
  "7.1": {
    "03": {
      "04": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.30",
          "patch":"(IV83993m4b)"
        }
      },
      "05": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.45",
          "patch":"(IV83993m5a)"
        }
      },
      "06": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.46",
          "patch":"(IV83993m6a)"
        }
      },
      "07": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.47",
          "patch":"(IV83993s7a)"
        }
      }
    },
    "04": {
      "00": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.1",
          "patch":"(IV83994m1a)"
        }
      },
      "01": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.1",
          "patch":"(IV83994m1a)"
        }
      },
      "02": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.1",
          "patch":"(IV83994s2a)"
        }
      }
    }
  },
  "7.2": {
   "00": {
      "00": {
        "bos.net.tcp.ntp": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.2",
          "patch":"(IV83995m0a)"
        },
        "bos.net.tcp.ntpd": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.2",
          "patch":"(IV83995m0a)"
        }
      },
      "01": {
        "bos.net.tcp.ntp": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.2",
          "patch":"(IV83995m1a)"
        },
        "bos.net.tcp.ntpd": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.2",
          "patch":"(IV83995m1a)"
        }
      }
    }
  }
};

version_report = "AIX " + oslevel;
if ( empty_or_null(aix_ntp_vulns[oslevel]) ) {
  os_options = join( sort( keys(aix_ntp_vulns) ), sep:' / ' );
  audit(AUDIT_OS_NOT, os_options, version_report);
}

version_report = version_report + " ML " + ml;
if ( empty_or_null(aix_ntp_vulns[oslevel][ml]) ) {
  ml_options = join( sort( keys(aix_ntp_vulns[oslevel]) ), sep:' / ' );
  audit(AUDIT_OS_NOT, "ML " + ml_options, version_report);
}

version_report = version_report + " SP " + sp;
if ( empty_or_null(aix_ntp_vulns[oslevel][ml][sp]) ) {
  sp_options = join( sort( keys(aix_ntp_vulns[oslevel][ml]) ), sep:' / ' );
  audit(AUDIT_OS_NOT, "SP " + sp_options, version_report);
}

foreach package ( keys(aix_ntp_vulns[oslevel][ml][sp]) ) {
  package_info = aix_ntp_vulns[oslevel][ml][sp][package];
  minfilesetver = package_info["minfilesetver"];
  maxfilesetver = package_info["maxfilesetver"];
  patch =         package_info["patch"];
  if (aix_check_ifix(release:oslevel, ml:ml, sp:sp, patch:patch, package:package, minfilesetver:minfilesetver, maxfilesetver:maxfilesetver) < 0) flag++;
}

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bos.net.tcp.ntp / bos.net.tcp.ntpd / bos.net.tcp.client");
}
