#TRUSTED 297c9c3009dcfd38679bd6109b429b3c584327044e24dcf449ef7e2ae8161b8c8bc5f86661613604ee52f6f219f3870b8c0261c6b0d5452170032b65bda1b664410657bea5058491ed4a21ba28f06d931df3acb5a7a3f3021af110dff9c4cb5203af37a8d0e3d3b4a90f0744489d0ffeb7c4873da065922d75f85a499d09ef6438fc19dfab053e0c2d7974842a2c31667265c895281b14bb4a831b1ebaad181d1aabf477ce4eaeaed47f9d02c5525191b93755e174fe1d81c16eed65dc12c7f78e080c6151bb6a0b8cddc73dd6110ed83040eb7dbfaa12c36ee6cfefa95648eb38ea9aaeb335f7bd5ebbd6ece7952c1e119df4ffd0058ba4035ddb4a0068d3bf33a43ea0ce534fb2664e52d3ed801a2024cbe7254a7e17e30ad04566f3b49d3cd276d0ca9efd303e676d5f0ecdee8f27db980eb4ae4e92834a346b21f520e10a3a5b30106208edc6aa0ca6a5b8ecf6b1045fa8496d8d64a62c942456dda53a32b0ede579d4cb98065fca3f05aa5d41f6123f6f42a4ec5e18d7b3cfa9f2c735f2c54d8959659f2f68eb8dffd0e1950800d17019be103b3e533f2f0886d6218b046a1bc769bc2bc2480e05f72c3415e7141b3f88758218594db1946bb6a307eb53d83c2c6c8fa496fea947d4db8c706a0357a842ef342ac7b511c7322c474ea5e11d19ceff298005f74d37d03b3c54bf246b732775561a629313a07426da644c82
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision 1.41
#

###
# Audit template standards:
#
# - The result of actions should be described in the past tense.
# - Contractions should not be used.
# - 'failed to' is preferred over 'could not'.
# - 'not affected' is preferred over 'not vulnerable'.
###

global_var _audit_id;

_audit_id = 0;

##
# The given software has not been installed.
#
# @remark Exit code 0.
# @remark $1$ does not appear to be installed. (application name)
##
global_var AUDIT_NOT_INST;
AUDIT_NOT_INST = _audit_id++;

##
# The installed software/version is not vulnerable.
#
# @remark Exit code 0.
# @remark $1$ is installed and not affected. (application name)
# @remark $1$ version $2$ is installed and not affected. (application name, version)
# @remark $1$, version $2$, build $3$ is installed and not affected. (application name, version, build)
# @remark $2$ may be passed as a list for multiple non-affected versions
##
global_var AUDIT_INST_VER_NOT_VULN;
AUDIT_INST_VER_NOT_VULN = _audit_id++;

##
# The installed software/version is potentially affected
# Used for cases where AUDIT_PARANOID is conditional and Settings/ParanoidReport# is not a required key.
#
# @remark Exit code 0.
# @remark The $1$ install is potentially affected and therefore is only reported if 'Report Paranoia' is set to 'Paranoid'. (application name)
# @remark The $1$ version $2$ install is potentially affected and therefore is only reported if 'Report Paranoia' is set to 'Paranoid'. (application name, version)
# @remark The $1$ version $2$ install on port $3$ is potentially affected and therefore is only reported if 'Report Paranoia' is set to 'Paranoid'. (application name, version, port)

##
global_var AUDIT_POTENTIAL_VULN;
AUDIT_POTENTIAL_VULN = _audit_id++;

##
# Unknown application version
#
# @remark Exit code 1.
# @remark The version of $1$ could not be determined. (application name)
##
global_var AUDIT_UNKNOWN_APP_VER;
AUDIT_UNKNOWN_APP_VER = _audit_id++;

##
# Unknown application build
#
# @remark Exit code 1.
# @remark The build of $1$ could not be determined. (application name)
# @remark The build of $1$, version $2$, could not be determined. (application name, version)
##
global_var AUDIT_UNKNOWN_BUILD;
AUDIT_UNKNOWN_BUILD = _audit_id++;


##
# The version number is not granular enough to determine if vulnerable
#
# @remark Exit code 0.
# @remark The install of $1$, with a version of $2$, is not granular enough to make a determination. (application name, version)
# @remark The install of $1$ on port $2$, with a version of $3$, is not granular enough to make a determination. (application name, port, version)
##
global_var AUDIT_VER_NOT_GRANULAR;
AUDIT_VER_NOT_GRANULAR = _audit_id++;

##
# Windows server core is not affected.
#
# @remark Exit code 0.
# @remark Windows Server Core installs are not affected.
##
global_var AUDIT_WIN_SERVER_CORE;
AUDIT_WIN_SERVER_CORE = _audit_id++;

##
# The Windows host is listed in a Microsoft bulletin as "Not affected" based on its OS version and/or SP
#
# @remark Exit code 0.
# @remark Host is not affected based on its version / service pack.
##
global_var AUDIT_OS_SP_NOT_VULN;
AUDIT_OS_SP_NOT_VULN = _audit_id++;

##
# The host is not configured in a vulnerable state
#
# @remark Exit code 0.
# @remark The remote $1$ host is not using a vulnerable configuration. (os/device name)
# @remark The remote $1$ version $2$ host is not using a vulnerable configuration. (os/device name, version)
##
global_var AUDIT_OS_CONF_NOT_VULN;
AUDIT_OS_CONF_NOT_VULN = _audit_id++;

##
# The installed software/path is not vulnerable.
#
# @remark Exit code 0.
# @remark $1$ is installed and not affected. (application name)
# @remark $1$ version $2$ is installed and not affected. (application name, path)
# @remark The $1$ version $2$ install under $3$ is not affected. (application name, version, path)
##
global_var AUDIT_INST_PATH_NOT_VULN;
AUDIT_INST_PATH_NOT_VULN = _audit_id++;

##
# The path could not be determined
#
# @remark Exit code 1.
# @remark Failed to get the $1 directory (Directory Name)
##
global_var AUDIT_PATH_NOT_DETERMINED;
AUDIT_PATH_NOT_DETERMINED = _audit_id++;

#
# A Patch has been installed.
#
# @remark Exit code 0.
# @remark The specified patch $1$ has been installed. (patch ID)
# @remark $2$ has the patch $1$ installed. (patch ID, product)
# @remark $2$ $3$ has the patch $1$ installed. (patch ID, product, version)
#
global_var AUDIT_PATCH_INSTALLED;
AUDIT_PATCH_INSTALLED = _audit_id++;

##
# The service is not listening on the given port.
#
# @remark Exit code 0.
# @remark $1$ does not appear to be listening on port $2$. (service name, port number)
# @remark $1$ does not appear to be listening on $3$ port $2$. (service name, port number, protocol)
##
global_var AUDIT_NOT_LISTEN;
AUDIT_NOT_LISTEN = _audit_id++;

##
# The service listening on the given port is not vulnerable.
#
# @remark Exit code 0.
# @remark The $1$ install listening on port $2$ is not affected. (service name, port number)
# @remark The $1$ $3$ install listening on port $2$ is not affected. (service name, port number, version)
# @remark The $1$ $3$ install listening on $4$ port $2$ is not affected. (service name, port number, version, protocol)
##
global_var AUDIT_LISTEN_NOT_VULN;
AUDIT_LISTEN_NOT_VULN = _audit_id++;

##
# The software is still supported by the vendor or unsupported version is
# not installed
#
# @remark Exit code 0.
# @remark An unsupported version of $1$ does not appear to be installed. (application name)
# @remark $1$ version $2$ is installed and is still supported. (application name, version)
# @remark $1$ version $2$ install under $3$ is still supported. (application name, version, path)
##
global_var AUDIT_SUPPORTED;
AUDIT_SUPPORTED = _audit_id++;

##
# The software appears to have been uninstalled uncleanly. This is
# used for situations where evidence of the application is found in
# the registry, but nothing can be found at the installation location.
#
# @remark Exit code 0.
# @remark $1$ no longer appears to be installed. (application name)
##
global_var AUDIT_UNINST;
AUDIT_UNINST = _audit_id++;

##
# The service/application was not detected. Used for remote plugins.
#
# @remark Exit code 0.
# @remark $1$ was not detected on this host. (service name)
# @remark $1$ was not detected on port $2$. (service name, port number)
##
global_var AUDIT_NOT_DETECT;
AUDIT_NOT_DETECT = _audit_id++;

##
# A WMI query returned the empty set.
#
# @remark Exit code 0.
# @remark A WMI query did not find any $1$ on the remote host. (db field)
##
global_var AUDIT_WMI_NONE;
AUDIT_WMI_NONE = _audit_id++;

##
# Unable to retrieve a banner remotely.
#
# @remark Exit code 0.
# @remark Did not receive a banner from the service listening on port $1$. (port number)
##
global_var AUDIT_NO_BANNER;
AUDIT_NO_BANNER = _audit_id++;

##
# The server responded with an error code or status.
#
# @remark Exit code 1.
# @remark Error received from the service listening on port $1$. (port number)
##
global_var AUDIT_SVC_ERR;
AUDIT_SVC_ERR = _audit_id++;

##
# Unable to connect to a network service.
#
# @remark Exit code 0.
# @remark Failed to connect to $1$ service listening on port $2$. (service name, port number)
##
global_var AUDIT_SVC_FAIL;
AUDIT_SVC_FAIL = _audit_id++;

##
# SSL negotiation failed.
#
# @remark Exit code 0.
# @remark Failed to negotiate $1$ on port $2$. (transport, port number)
##
global_var AUDIT_SSL_FAIL;
AUDIT_SSL_FAIL = _audit_id++;

##
# Socket creation failed.
#
# @remark Exit code 0.
# @remark Failed to open a socket on port $1$. (port number)
# @remark Failed to open a $2$ socket on port $1$. (port number, protocol)
##
global_var AUDIT_SOCK_FAIL;
AUDIT_SOCK_FAIL = _audit_id++;

##
# File open failed.
#
# @remark Exit code 0.
# @remark Failed to open the database '$1$'. (filename)
##
global_var AUDIT_INC_FAIL;
AUDIT_INC_FAIL = _audit_id++;

##
# A required function failed.
#
# @remark Exit code 1.
# @remark Function $1$() failed. (function name)
# @remark Function $1$() failed, returning $2$. (function name, return value)
##
global_var AUDIT_FN_FAIL;
AUDIT_FN_FAIL = _audit_id++;

##
# A required function is not defined.
#
# @remark Exit code 0.
# @remark Function $1$() is not defined. (function name)
##
global_var AUDIT_FN_UNDEF;
AUDIT_FN_UNDEF = _audit_id++;

##
# FTP server allows random usernames.
#
# @remark Exit code 0.
# @remark The FTP server on port $1$ allows random usernames. (port number)
##
global_var AUDIT_FTP_RANDOM_USER;
AUDIT_FTP_RANDOM_USER = _audit_id++;

##
# Required credentials have not been provided.
#
# @remark Exit code 0.
# @remark No $1$ credentials have been specified. (protocol)
##
global_var AUDIT_MISSING_CREDENTIALS;
AUDIT_MISSING_CREDENTIALS = _audit_id++;

##
# Web files not found.
#
# @remark Exit code 0.
# @remark No $1$ files were found hosted on the web server listening on port $2$. (app name, port number)
##
global_var AUDIT_WEB_FILES_NOT;
AUDIT_WEB_FILES_NOT = _audit_id++;

##
# Web banner not returned
#
# @remark Exit code 1.
# @remark Unable to get the web server banner on port $1$. (port number)
##
global_var AUDIT_WEB_BANNER_NOT;
AUDIT_WEB_BANNER_NOT = _audit_id++;

##
# Server response header not received
#
# @remark Exit code 0.
# @remark The web server listening on port $1$ does not send a Server response header. (port number)
##
global_var AUDIT_WEB_NO_SERVER_HEADER;
AUDIT_WEB_NO_SERVER_HEADER = _audit_id++;

##
# Incorrect web server detected
#
# @remark Exit code 0.
# @remark The web server on port $1$ is not $2$ (port number, web server name)
##
global_var AUDIT_WRONG_WEB_SERVER;
AUDIT_WRONG_WEB_SERVER = _audit_id++;

##
# Web server not affected
#
# @remark Exit code 0
# @remark The web server on port $1 is not affected (port)
global_var AUDIT_WEB_SERVER_NOT_AFFECTED;
AUDIT_WEB_SERVER_NOT_AFFECTED = _audit_id++;

##
# Unknown web server version
#
# @remark Exit code 1.
# @remark The version of $1$ listening on port $2$ could not be determined (web server name, port number)
##
global_var AUDIT_UNKNOWN_WEB_SERVER_VER;
AUDIT_UNKNOWN_WEB_SERVER_VER = _audit_id++;

##
# Web application not installed.
#
# @remark Exit code 0.
# @remark $1$ was not detected on the web server listening on port $2$. (app name, port number)
##
global_var AUDIT_WEB_APP_NOT_INST;
AUDIT_WEB_APP_NOT_INST = _audit_id++;

##
# Unknown web application version
#
# @remark Exit code 1.
# @remark The version of $1$ listening at $2$ could not be determined (web application name, url)
##
global_var AUDIT_UNKNOWN_WEB_APP_VER;
AUDIT_UNKNOWN_WEB_APP_VER = _audit_id++;

##
# Non-numeric application version
#
# @remark Exit code 1.
# @remark The version of $1$ listening on port $2$ - $3$ - is non-numeric and, therefore, cannot be used to make a determination. (application name, port number, version number)
##
global_var AUDIT_NONNUMERIC_VER;
AUDIT_NONNUMERIC_VER = _audit_id++;

##
# Web application not affected
#
# @remark Exit code 0
# @remark The $1 install at $2$ is not affected (web application name, url)
# @remark The $1$ install at $2$ is version $3$ and, therefore, is not affected (web application name, url, version number)
global_var AUDIT_WEB_APP_NOT_AFFECTED;
AUDIT_WEB_APP_NOT_AFFECTED = _audit_id++;

##
# Web application extension not affected
#
# @remark Exit code 0
# @remark The $3$ included in the $1$ install at $2$ is not affected (web application name, url, extension name)
# @remark The $3$ included in the $1$ install at $2$ is version $4$ and, therefore, is not affected (web application name, url, extension name, version number)
global_var AUDIT_WEB_APP_EXT_NOT_AFFECTED;
AUDIT_WEB_APP_EXT_NOT_AFFECTED = _audit_id++;

##
# Web application extension not installed
#
# @remark Exit code 0
# @remark The $1$ install at $2$ does not appear to have the $3$ (web application name, url, extension name)
global_var AUDIT_WEB_APP_EXT_NOT_INST;
AUDIT_WEB_APP_EXT_NOT_INST = _audit_id++;

##
# Web application is a supported version
#
# @remark Exit code 0
# @remark An unsupported version of $1$ does not appear to be installed. (web application name)
# @remark The $1$ install at $2$ is version $3$ and is still supported. (web application name, url, version
global_var AUDIT_WEB_APP_SUPPORTED;
AUDIT_WEB_APP_SUPPORTED = _audit_id++;

##
# Required policy preferences were not provided.
#
# @remark Exit code 0.
# @remark No $1$ preferences have been specified. (protocol/application/etc)
##
global_var AUDIT_MISSING_PREFERENCES;
AUDIT_MISSING_PREFERENCES = _audit_id++;

##
# A port tested by the plugin is not open.
#
# @remark Exit code 0.
# @remark Port $1$ is not open. (port number)
# @remark $2$ port $1$ is not open. (port number, protocol)
##
global_var AUDIT_PORT_CLOSED;
AUDIT_PORT_CLOSED = _audit_id++;

##
# A process is not running. This is used for credentialed plugins.
#
# @remark Exit code 0.
# @remark Remote host does not have $1$ running. (application/process name)
##
global_var AUDIT_PROC_OFF;
AUDIT_PROC_OFF = _audit_id++;

##
# A KB item is missing.
#
# @remark Exit code 0.
# @remark The '$1$' KB item is not set. (KB key name)
##
global_var AUDIT_KB_MISSING;
AUDIT_KB_MISSING = _audit_id++;

##
# A share or service is missing, so there's nothing to do.
#
# @remark Exit code 0.
# @remark The host does not seem to have any $1$. (shares/services/etc.)
##
global_var AUDIT_HOST_NONE;
AUDIT_HOST_NONE = _audit_id++;

##
# The remote host's OS is not affected.
#
# @remark Exit code 0.
# @remark The remote host's OS is not $1$. (expected OS)
# @remark The remote host's OS is $2$, not $1$. (expected OS, actual OS)
##
global_var AUDIT_OS_NOT;
AUDIT_OS_NOT = _audit_id++;

##
# The remote host's OS release is not affected.
#
# @remark Exit code 0.
# @remark The remote host's OS is $1$ release $2$. (OS, expected release)
# @remark The remote host's OS is $1$ release $3$, not $2$. (OS, expected release, actual release)
##
global_var AUDIT_OS_RELEASE_NOT;
AUDIT_OS_RELEASE_NOT = _audit_id++;

##
# The remote host is not an affected device.
#
# @remark Exit code 0.
# @remark The remote host is not $1$. (device name/device type)
##
global_var AUDIT_HOST_NOT;
AUDIT_HOST_NOT = _audit_id++;

##
# The remote host version is not available.
#
# @remark Exit code 0.
# @remark The $1$ version is not available (the remote host may not be $1$). (device name/device type)
##
global_var AUDIT_UNKNOWN_DEVICE_VER;
AUDIT_UNKNOWN_DEVICE_VER = _audit_id++;

##
# The remote host version is not available.
#
# @remark Exit code 0.
# @remark $1$ is not an affected device. (device name/device type)
# @remark $1$ is running firmware $2$ and is not affected. (device name, version)
##
global_var AUDIT_DEVICE_NOT_VULN;
AUDIT_DEVICE_NOT_VULN = _audit_id++;

##
# A network service did not respond to a request.
#
# @remark Exit code 0.
# @remark The service listening on port $1$ did not respond. (port number)
# @remark The service listening on port $1$ did not respond to $2$. (port number, request description)
# @remark The service listening on $3$ port $1$ did not respond to $2$. (port number, request description, protocol)
##
global_var AUDIT_RESP_NOT;
AUDIT_RESP_NOT = _audit_id++;

##
# The server sent an invalid/unexpected response (e.g., protocol violation).
#
# @remark Exit code 0.
# @remark The service listening on port $1$ did not respond as expected. (port number)
# @remark The service listening on port $1$ did not respond as expected to $2$. (port number, request description)
# @remark The service listening on $3$ port $1$ did not respond as expected to $2$. (port number, request description, protocol)
##
global_var AUDIT_RESP_BAD;
AUDIT_RESP_BAD = _audit_id++;

##
# No unknown services were detected.
#
# @remark Exit code 0.
# @remark There are no unknown services.
##
global_var AUDIT_SVC_KNOWN;
AUDIT_SVC_KNOWN = _audit_id++;

##
# The service has already been identified.
#
# @remark Exit code 0.
# @remark The service listening on port $1$ has already been identified. (port number)
##
global_var AUDIT_SVC_ALREADY_KNOWN;
AUDIT_SVC_ALREADY_KNOWN = _audit_id++;

##
# The service is not silent.
#
# @remark Exit code 0.
# @remark The service listening on port $1$ is not silent. (port number)
##
global_var AUDIT_SVC_NOT_SILENT;
AUDIT_SVC_NOT_SILENT = _audit_id++;

##
# The service is silent.
#
# @remark Exit code 0.
# @remark The service listening on port $1$ is silent. (port number)
##
global_var AUDIT_SVC_SILENT;
AUDIT_SVC_SILENT = _audit_id++;

##
# The plugin only runs during paranoid scans.
#
# @remark Exit code 1.
# @remark This plugin only runs if 'Report paranoia' is set to 'Paranoid'.
##
global_var AUDIT_PARANOID;
AUDIT_PARANOID = _audit_id++;


##
# Security patches may have been backported
#
# @remark Exit code 0.
# @remark Security patches may have been backported on the service listening on port $1$ (port number)
# @remark Security patches may have been backported on the $2$ listening on port $1$ (port number, service)
##
global_var AUDIT_BACKPORT_SERVICE;
AUDIT_BACKPORT_SERVICE = _audit_id++;

##
# The plugin only runs during thorough scans.
#
# @remark Exit code 1.
# @remark This plugin only runs if 'Thorough tests' is enabled.
##
global_var AUDIT_THOROUGH;
AUDIT_THOROUGH = _audit_id++;

##
# The plugin only runs over IPv4.
#
# @remark Exit code 1.
# @remark This plugin only runs in IPv4.
##
global_var AUDIT_ONLY_IPV4;
AUDIT_ONLY_IPV4 = _audit_id++;

##
# The plugin can not check against the localhost.
#
# @remark Exit code 1.
# @remark Cannot check against localhost.
##
global_var AUDIT_LOCALHOST;
AUDIT_LOCALHOST = _audit_id++;

##
# An ActiveX control was not found.
#
# @remark Exit code 0.
# @remark The control is not installed as the class id '$1$' does not exist on the remote host. (GUID)
##
global_var AUDIT_ACTIVEX_NOT_FOUND;
AUDIT_ACTIVEX_NOT_FOUND = _audit_id++;

##
# The ActiveX control is installed, but its kill bit is set.
#
# @remark Exit code 0.
# @remark An unknown version of the control is installed, but its kill bit is set.
# @remark Version $1$ of the control is installed, but its kill bit is set. (file version number)
##
global_var AUDIT_ACTIVEX;
AUDIT_ACTIVEX = _audit_id++;

##
# PCI-DSS compliance checking has not been enabled.
#
# @remark Exit code 0.
# @remark PCI-DSS compliance checking is not enabled.
##
global_var AUDIT_PCI;
AUDIT_PCI = _audit_id++;

##
# Unable to connect to SMB share.
#
# @remark Exit code 1.
# @remark Failed to connect to the '$1$' share. (share name)
##
global_var AUDIT_SHARE_FAIL;
AUDIT_SHARE_FAIL = _audit_id++;

##
# Unable to connect to WMI namespace.
#
# @remark Exit code 1.
# @remark Failed to connect to the '$1$' WMI namespace. (WMI namespace)
##
global_var AUDIT_WMI_FAIL;
AUDIT_WMI_FAIL = _audit_id++;

##
# Unable to connect to registry.
#
# @remark Exit code 1.
# @remark Failed to connect to the remote registry.
##
global_var AUDIT_REG_FAIL;
AUDIT_REG_FAIL = _audit_id++;

##
# Unable to get file version.
#
# @remark Exit code 1.
# @remark Failed to get the file version of $1$. (pathname)
##
global_var AUDIT_VER_FAIL;
AUDIT_VER_FAIL = _audit_id++;

##
# Incorrect or unexpected version format.
#
# @remark Exit code 1.
# @remark The version, $1$, does not appear to be valid. (version)
##
global_var AUDIT_VER_FORMAT;
AUDIT_VER_FORMAT = _audit_id++;

##
# Unable to get a service version.
#
# @remark Exit code 0.
# @remark Failed to get the version of the $1$ service on port $2$. (service name, port)
##
global_var AUDIT_SERVICE_VER_FAIL;
AUDIT_SERVICE_VER_FAIL = _audit_id++;

##
# The plugin only runs when the policy allows log in attempts for
# accounts whose credentials were not provided by the user
#
# @remark Exit code 1.
# @remark Nessus is currently configured to not log in with user accounts not specified in the scan policy.
##
global_var AUDIT_SUPPLIED_LOGINS_ONLY;
AUDIT_SUPPLIED_LOGINS_ONLY = _audit_id++;

##
# Local checks are not enabled.
#
# @remark Exit code 0.
# @remark Local checks are not enabled.
##
global_var AUDIT_LOCAL_CHECKS_NOT_ENABLED;
AUDIT_LOCAL_CHECKS_NOT_ENABLED = _audit_id++;

##
# Local checks are not enabled.
#
# @remark Exit code 1.
# @remark Local checks for $1$ on the '$2$' architecture have not been implemented. (OS name, architecture)
##
global_var AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED;
AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED = _audit_id++;

##
# The host's architecture is not a match.
#
# @remark Exit code 0.
# @remark The host's architecture is not $1$. (expected_)
# @remark The host's architecture is $2$, not $1$. (expected, actual)
##
global_var AUDIT_ARCH_NOT;
AUDIT_ARCH_NOT = _audit_id++;

##
# Failed to determine the host's architecture.
#
# @remark Exit code 0.
# @remark Local checks are not enabled.
##
global_var AUDIT_UNKNOWN_ARCH;
AUDIT_UNKNOWN_ARCH = _audit_id++;

##
# List of installed packages is missing.
#
# @remark Exit code 1.
# @remark Failed to obtain the list of installed packages.
# @remark Failed to obtain the list of installed $1$. (packaging system name)
##
global_var AUDIT_PACKAGE_LIST_MISSING;
AUDIT_PACKAGE_LIST_MISSING = _audit_id++;

##
# Package(s) not installed.
#
# @remark Exit code 0.
# @remark The $1$ package is not installed. (package name(s))
##
global_var AUDIT_PACKAGE_NOT_INSTALLED;
AUDIT_PACKAGE_NOT_INSTALLED = _audit_id++;

##
# Installed package(s) not affected.
#
# @remark Exit code 0.
# @remark The $1$ package is installed and not affected. (packaging name(s))
##
global_var AUDIT_PACKAGE_NOT_AFFECTED;
AUDIT_PACKAGE_NOT_AFFECTED = _audit_id++;

##
# Host is not managed by the current Patch Management software.
#
# @remark Exit code 0.
# @remark The host is not managed by $1$. (patch management name)
##
global_var AUDIT_HOST_NOT_MANAGED;
AUDIT_HOST_NOT_MANAGED = _audit_id++;

##
# The Red Hat Host is not affected by a particular RHSA advisory.
#
# @remark Exit code 0.
# @remark The remote RedHat host is not susceptible to security advisory $1$. (RHSA id)
# @remark The remote RedHat $1$ host is not susceptible to security advisory $2$. (OS level, RHSA id)
##
global_var AUDIT_RHSA_NOT_AFFECTED;
AUDIT_RHSA_NOT_AFFECTED = _audit_id++;

# The AUDIT_AUDIT_* IDs are only meant to be used internally by this library,
# so they won't be given nasldoc headers.

#
# An audit ID was not provided to audit()
#
# @remark Exit code 1.
# @remark audit() was not passed any arguments.
#
global_var AUDIT_AUDIT_MISSING;
AUDIT_AUDIT_MISSING = _audit_id++;

#
# An invalid audit ID was provided to audit().
#
# @remark Exit code 1.
# @remark audit() was passed an unknown identifier: '$1$'. (ID)
#
global_var AUDIT_AUDIT_UNKNOWN;
AUDIT_AUDIT_UNKNOWN = _audit_id++;

#
# The number of arguments don't match the number of tags in the format string.
#
# @remark Exit code 1.
# @remark audit() was passed $1$ parameter(s) for identifier $2$, but there are no format strings that match.
#
global_var AUDIT_AUDIT_MISMATCH;
AUDIT_AUDIT_MISMATCH = _audit_id++;

#
# The audit template doesn't include an exit code.
#
# @remark Exit code 1.
# @remark Audit template $1$ does not contain an exit code.
#
global_var AUDIT_AUDIT_CODE_MISSING;
AUDIT_AUDIT_CODE_MISSING = _audit_id++;

#
# A NULL argument was provided to the format string of an audit template.
#
# @remark Exit code 1.
# @remark Audit template $1$ was passed a NULL value. (audit ID)
#
global_var AUDIT_AUDIT_NULL_ARG;
AUDIT_AUDIT_NULL_ARG = _audit_id++;

#
# A non-string argument was provided to the format string of an audit template.
#
# @remark Exit code 1.
# @remark Audit template $1$ was passed an array value: $2$. (audit ID, array arg)
#
global_var AUDIT_AUDIT_ARRAY_ARG;
AUDIT_AUDIT_ARRAY_ARG = _audit_id++;

##
# Gets an audit message structure.
#
# @anonparam id ID of audit message structure to retrieve.
#
# @return An audit message hash, or NULL if an audit message couldn't be found for 'id'.
#         ret['code'] - exit code.
#         ret[i] - audit message format string, where 'i' is the number of substitutions in the string.
##
function get_audit_message()
{
  local_var audit_id;

  # Sanity check parameters.
  audit_id = _FCT_ANON_ARGS[0];
  if (isnull(audit_id))
    return NULL;

  if (audit_id == AUDIT_NOT_INST)
  {
    return make_array(
      "code", 0,
      1, "$1$ does not appear to be installed."
    );
  }
  else if (audit_id == AUDIT_INST_VER_NOT_VULN)
  {
    return make_array(
      "code", 0,
      1, "$1$ is installed and not affected.",
      2, "$1$ version $2$ is installed and not affected.",
      3, "$1$, version $2$, build $3$ is installed and not affected."
    );
  }
  else if (audit_id == AUDIT_POTENTIAL_VULN)
  {
    return make_array(
      "code", 0,
      1, "The $1$ install is potentially affected and therefore is only reported if 'Report Paranoia' is set to 'Paranoid'.",
      2, "The $1$ version $2$ install is potentially affected and therefore is only reported if 'Report Paranoia' is set to 'Paranoid'.",
      3, "The $1$ version $2$ install on port $3$ is potentially affected and therefore is only reported if 'Report Paranoia' is set to 'Paranoid'."
    );
  }
  else if (audit_id == AUDIT_UNKNOWN_APP_VER)
  {
    return make_array(
      "code", 1,
      1, "The version of $1$ could not be determined."
    );
  }
   else if (audit_id == AUDIT_UNKNOWN_BUILD)
  {
    return make_array(
      "code", 1,
      1, "The build of $1$ could not be determined.",
      2, "The build of $1$, version $2$, could not be determined."
    );
  }
  else if (audit_id == AUDIT_VER_NOT_GRANULAR)
  {
    return make_array(
      "code", 0,
      2, "The install of $1$, with a version of $2$, is not granular enough to make a determination.",
      3, "The install of $1$ on port $2$, with a version of $3$, is not granular enough to make a determination."
    );
  }
  else if (audit_id == AUDIT_WIN_SERVER_CORE)
  {
    return make_array(
      "code", 0,
      0, "Windows Server Core installs are not affected."
    );
  }
  else if (audit_id == AUDIT_OS_SP_NOT_VULN)
  {
    return make_array(
      "code", 0,
      0, "The host is not affected based on its version / service pack."
    );
  }
  else if (audit_id == AUDIT_OS_CONF_NOT_VULN)
  {
    return make_array(
      "code", 0,
      1, "The remote $1$ host is not using a vulnerable configuration.",
      2, "The remote $1$ version $2$ host is not using a vulnerable configuration."
    );
  }
  else if (audit_id == AUDIT_INST_PATH_NOT_VULN)
  {
    return make_array(
      "code", 0,
      1, "$1$ is installed and not affected.",
      2, "$1$ installed at $2$ is not affected.",
      3, "The $1$ version $2$ install under $3$ is not affected."
    );
  }
  else if (audit_id == AUDIT_PATH_NOT_DETERMINED)
  {
    return make_array(
      "code", 1,
      1, "Failed to get the $1$ directory."
    );
  }
  else if (audit_id == AUDIT_PATCH_INSTALLED)
  {
    return make_array(
      "code", 0,
      1, "The specified patch $1$ has been installed.",
      2, "$2$ has the patch $1$ installed.",
      3, "$2$ $3$ has the patch $1$ installed."
    );
  }
  else if (audit_id == AUDIT_NOT_LISTEN)
  {
    return make_array(
      "code", 0,
      2, "$1$ does not appear to be listening on port $2$.",
      3, "$1$ does not appear to be listening on $3$ port $2$."
    );
  }
  else if (audit_id == AUDIT_LISTEN_NOT_VULN)
  {
    return make_array(
      "code", 0,
      2, "The $1$ install listening on port $2$ is not affected.",
      3, "The $1$ $3$ install listening on port $2$ is not affected.",
      4, "The $1$ $3$ install listening on $4$ port $2$ is not affected."
    );
  }
  else if (audit_id == AUDIT_SUPPORTED)
  {
    return make_array(
      "code", 0,
      1, "An unsupported version of $1$ does not appear to be installed.",
      2, "$1$ version $2$ is installed and is still supported.",
      3, "$1$ version $2$ install under $3$ is still supported."
    );
  }
  else if (audit_id == AUDIT_UNINST)
  {
    return make_array(
      "code", 0,
      1, "$1$ no longer appears to be installed."
    );
  }
  else if (audit_id == AUDIT_NOT_DETECT)
  {
    return make_array(
      "code", 0,
      1, "$1$ was not detected on this host.",
      2, "$1$ was not detected on port $2$."
    );
  }
  else if (audit_id == AUDIT_WMI_NONE)
  {
    return make_array(
      "code", 0,
      1, "A WMI query did not find any $1$ on the remote host."
    );
  }
  else if (audit_id == AUDIT_NO_BANNER)
  {
    return make_array(
      "code", 0,
      1, "Did not receive a banner from the service listening on port $1$."
    );
  }
  else if (audit_id == AUDIT_SVC_ERR)
  {
    return make_array(
      "code", 0,
      1, "Error received from the service listening on port $1$."
    );
  }
  else if (audit_id == AUDIT_SVC_FAIL)
  {
    return make_array(
      "code", 0,
      2, "Failed to connect to $1$ service listening on port $2$."
    );
  }
  else if (audit_id == AUDIT_SSL_FAIL)
  {
    return make_array(
      "code", 0,
      2, "Failed to negotiate $1$ on port $2$."
    );
  }
  else if (audit_id == AUDIT_SOCK_FAIL)
  {
    return make_array(
      "code", 1,
      1, "Failed to open a socket on port $1$.",
      2, "Failed to open a $2$ socket on port $1$."
    );
  }
  else if (audit_id == AUDIT_INC_FAIL)
  {
    return make_array(
      "code", 0,
      1, "Failed to open the database '$1$'."
    );
  }
  else if (audit_id == AUDIT_FN_FAIL)
  {
    return make_array(
      "code", 1,
      1, "Function $1$() failed.",
      2, "Function $1$() failed, returning $2$."
    );
  }
  else if (audit_id == AUDIT_FN_UNDEF)
  {
    return make_array(
      "code", 0,
      1, "Function $1$() is not defined."
    );
  }
  else if (audit_id == AUDIT_FTP_RANDOM_USER)
  {
    return make_array(
      "code", 0,
      1, "The FTP server on port $1$ allows random usernames."
    );
  }
  else if (audit_id == AUDIT_MISSING_CREDENTIALS)
  {
    return make_array(
      "code", 0,
      1, "No $1$ credentials have been specified."
    );
  }
  else if (audit_id == AUDIT_WEB_FILES_NOT)
  {
    return make_array(
      "code", 0,
      2, "No $1$ files were found hosted on the web server listening on port $2$."
    );
  }
  else if (audit_id == AUDIT_WEB_BANNER_NOT)
  {
    return make_array(
      "code", 1,
      1, "Unable to get the web server banner on port $1$."
    );
  }
  else if (audit_id == AUDIT_WEB_NO_SERVER_HEADER)
  {
    return make_array(
      "code", 0,
      1, "The web server listening on port $1$ does not send a Server response header."
    );
  }
  else if (audit_id == AUDIT_WRONG_WEB_SERVER)
  {
    return make_array(
      "code", 0,
      2, "The web server on port $1$ is not $2$."
    );
  }
  else if (audit_id == AUDIT_WEB_SERVER_NOT_AFFECTED)
  {
    return make_array(
      "code", 0,
      1, "The web server on port $1$ is not affected."
    );
  }
  else if (audit_id == AUDIT_UNKNOWN_WEB_SERVER_VER)
  {
    return make_array(
      "code", 1,
      2, "The version of $1$ listening on port $2$ could not be determined."
    );
  }
  else if (audit_id == AUDIT_WEB_APP_NOT_INST)
  {
    return make_array(
      "code", 0,
      2, "$1$ was not detected on the web server listening on port $2$."
    );
  }
  else if (audit_id == AUDIT_UNKNOWN_WEB_APP_VER)
  {
    return make_array(
      "code", 1,
      2, "The version of $1$ listening at $2$ could not be determined."
    );
  }
  else if (audit_id == AUDIT_NONNUMERIC_VER)
  {
    return make_array(
      "code", 1,
      3, "The version of $1$ listening on port $2$ - $3$ - is non-numeric and, therefore, cannot be used to make a determination."
    );
  }
  else if (audit_id == AUDIT_WEB_APP_NOT_AFFECTED)
  {
    return make_array(
      "code", 0,
      2, "The $1$ install at $2$ is not affected.",
      3, "The $1$ install at $2$ is version $3$ and, therefore, is not affected."
    );
  }
  else if (audit_id == AUDIT_WEB_APP_EXT_NOT_AFFECTED)
  {
    return make_array(
      "code", 0,
      3, "The $3$ included in the $1$ install at $2$ is not affected.",
      4, "The $3$ included in the $1$ install at $2$ is version $4$ and, therefore, is not affected."
    );
  }
  else if (audit_id == AUDIT_WEB_APP_EXT_NOT_INST)
  {
    return make_array(
    "code", 0,
    3, "The $1$ install at $2$ does not appear to have the $3$."
    );
  }
  else if (audit_id == AUDIT_WEB_APP_SUPPORTED)
  {
    return make_array(
      "code", 0,
      1, "An unsupported version of $1$ does not appear to be installed.",
      3, "The $1$ install at $2$ is version $3$ and is still supported."
    );
  }
  else if (audit_id == AUDIT_MISSING_PREFERENCES)
  {
    return make_array(
      "code", 0,
      1, "No $1$ preferences have been specified."
    );
  }
  else if (audit_id == AUDIT_PORT_CLOSED)
  {
    return make_array(
      "code", 0,
      1, "Port $1$ is not open.",
      2, "$2$ port $1$ is not open."
    );
  }
  else if (audit_id == AUDIT_PROC_OFF)
  {
    return make_array(
      "code", 0,
      1, "The remote host does not have $1$ running."
    );
  }
  else if (audit_id == AUDIT_KB_MISSING)
  {
    return make_array(
      "code", 0,
      1, "The '$1$' KB item is not set."
    );
  }
  else if (audit_id == AUDIT_HOST_NONE)
  {
    return make_array(
      "code", 0,
      1, "The host does not seem to have any $1$."
    );
  }
  else if (audit_id == AUDIT_OS_NOT)
  {
    return make_array(
      "code", 0,
      1, "The remote host's OS is not $1$.",
      2, "The remote host's OS is $2$, not $1$."
    );
  }
  else if (audit_id == AUDIT_OS_RELEASE_NOT)
  {
    return make_array(
      "code", 0,
      2, "The remote host's OS is $1$ release $2$.",
      3, "The remote host's OS is $1$ release $3$, not $2$."
    );
  }
  else if (audit_id == AUDIT_HOST_NOT)
  {
    return make_array(
      "code", 0,
      1, "The remote host is not $1$."
    );
  }
  else if (audit_id == AUDIT_UNKNOWN_DEVICE_VER)
  {
    return make_array(
      "code", 0,
      1, "The $1$ version is not available (the remote host may not be $1$)."
    );
  }
  else if (audit_id == AUDIT_DEVICE_NOT_VULN)
  {
    return make_array(
      "code", 0,
      1, "$1$ is not an affected device.",
      2, "$1$ is running firmware $2$ and is not affected."
    );
  }
  else if (audit_id == AUDIT_RESP_NOT)
  {
    return make_array(
      "code", 0,
      1, "The service listening on port $1$ did not respond.",
      2, "The service listening on port $1$ did not respond to $2$.",
      3, "The service listening on $3$ port $1$ did not respond to $2$."
    );
  }
  else if (audit_id == AUDIT_RESP_BAD)
  {
    return make_array(
      "code", 0,
       1, "The service listening on port $1$ did not respond as expected.",
       2, "The service listening on port $1$ did not respond as expected to $2$.",
       3, "The service listening on $3$ port $1$ did not respond as expected to $2$."
    );
  }
  else if (audit_id == AUDIT_SVC_KNOWN)
  {
    return make_array(
      "code", 0,
      0, "There are no unknown services."
    );
  }
  else if (audit_id == AUDIT_SVC_ALREADY_KNOWN)
  {
    return make_array(
      "code", 0,
      1, "The service listening on port $1$ has already been identified."
    );
  }
  else if (audit_id == AUDIT_SVC_NOT_SILENT)
  {
    return make_array(
      "code", 0,
      1, "The service listening on port $1$ is not silent."
    );
  }
  else if (audit_id == AUDIT_SVC_SILENT)
  {
    return make_array(
      "code", 0,
      1, "The service listening on port $1$ is silent."
    );
  }
  else if (audit_id == AUDIT_PARANOID)
  {
    return make_array(
      "code", 1,
      0, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'."
    );
  }
  else if (audit_id == AUDIT_BACKPORT_SERVICE)
  {
    return make_array(
      "code", 0,
      1, "Security patches may have been backported on the service listening on port $1$.",
      2, "Security patches may have been backported on the $2$ listening on port $1$."
    );
  }
  else if (audit_id == AUDIT_THOROUGH)
  {
    return make_array(
      "code", 1,
      0, "This plugin only runs if 'Thorough tests' is enabled."
    );
  }
  else if (audit_id == AUDIT_ONLY_IPV4)
  {
    return make_array(
      "code", 1,
      0, "This plugin only runs in IPv4."
    );
  }
  else if (audit_id == AUDIT_LOCALHOST)
  {
    return make_array(
      "code", 1,
      0, "Cannot check against localhost."
    );
  }
  else if (audit_id == AUDIT_ACTIVEX_NOT_FOUND)
  {
    return make_array(
      "code", 0,
      1, "The control is not installed as the class id '$1$' does not exist on the remote host."
    );
  }
  else if (audit_id == AUDIT_ACTIVEX)
  {
    return make_array(
      "code", 0,
      0, "The control is installed, but its kill bit is set.",
      1, "Version $1$ of the control is installed, but its kill bit is set."
    );
  }
  else if (audit_id == AUDIT_PCI)
  {
    return make_array(
      "code", 0,
      0, "PCI-DSS compliance checking is not enabled."
    );
  }
  else if (audit_id == AUDIT_SHARE_FAIL)
  {
    return make_array(
      "code", 1,
      1, "Failed to connect to the '$1$' share."
    );
  }
  else if (audit_id == AUDIT_WMI_FAIL)
  {
    return make_array(
      "code", 1,
      1, "Failed to connect to the '$1$' WMI namespace."
    );
  }
  else if (audit_id == AUDIT_REG_FAIL)
  {
    return make_array(
      "code", 1,
      0, "Failed to connect to the remote registry."
    );
  }
  else if (audit_id == AUDIT_SUPPLIED_LOGINS_ONLY)
  {
    return make_array(
      "code", 1,
      0, "Nessus is currently configured to not log in with user accounts not specified in the scan policy."
    );
  }
  else if (audit_id == AUDIT_LOCAL_CHECKS_NOT_ENABLED)
  {
    return make_array(
      "code", 0,
      0, "Local checks are not enabled."
    );
  }
  else if (audit_id == AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED)
  {
    return make_array(
      "code", 1,
      2, "Local checks for $1$ on the '$2$' architecture have not been implemented."
    );
  }
  else if (audit_id == AUDIT_ARCH_NOT)
  {
    return make_array(
      "code", 0,
      1, "The host's architecture is not $1$.",
      2, "The host's architecture is $2$, not $1$."
    );
  }
  else if (audit_id == AUDIT_UNKNOWN_ARCH)
  {
    return make_array(
      "code", 1,
      0, "Failed to determine the host's architecture."
    );
  }
  else if (audit_id == AUDIT_PACKAGE_LIST_MISSING)
  {
    return make_array(
      "code", 1,
      0, "Failed to obtain the list of installed packages.",
      1, "Failed to obtain the list of installed $1$."
    );
  }
  else if (audit_id == AUDIT_PACKAGE_NOT_INSTALLED)
  {
    return make_array(
      "code", 0,
      1, "The $1$ package is not installed."
    );
  }
  else if (audit_id == AUDIT_PACKAGE_NOT_AFFECTED)
  {
    return make_array(
      "code", 0,
      1, "The $1$ package is installed and not affected."
    );
  }
  else if (audit_id == AUDIT_HOST_NOT_MANAGED)
  {
  	return make_array(
  	  "code", 0,
  	  1, "The host is not managed by $1$."
  	);
  }
  else if (audit_id == AUDIT_RHSA_NOT_AFFECTED)
  {
    return make_array(
      "code", 0,
      1, "The remote RedHat host is not susceptible to security advisory $1$.",
      2, "The remote RedHat $1$ host is not susceptible to security advisory $2$
."
    );
  }
  else if (audit_id == AUDIT_VER_FAIL)
  {
    return make_array(
      "code", 1,
      1, "Failed to get the file version of $1$."
    );
  }
  else if (audit_id == AUDIT_VER_FORMAT)
  {
    return make_array(
      "code", 1,
      1, "The version, $1$, does not appear to be valid."
    );
  }
  else if (audit_id == AUDIT_SERVICE_VER_FAIL)
  {
    return make_array(
      "code", 0,
      2, "Failed to get the version of the $1$ service on port $2$."
    );
  }
  else if (audit_id == AUDIT_AUDIT_MISSING)
  {
    return make_array(
      "code", 1,
      0, "audit() was not passed any arguments."
    );
  }
  else if (audit_id == AUDIT_AUDIT_UNKNOWN)
  {
    return make_array(
      "code", 1,
      1, "audit() was passed an unknown identifier: '$1$'."
    );
  }
  else if (audit_id == AUDIT_AUDIT_MISMATCH)
  {
    return make_array(
      "code", 1,
      2, "audit() was passed $1$ parameter(s) for identifier $2$, but there are no format strings that match."
    );
  }
  else if (audit_id == AUDIT_AUDIT_CODE_MISSING)
  {
    return make_array(
      "code", 1,
      1, "Audit template $1$ does not contain an exit code."
    );
  }
  else if (audit_id == AUDIT_AUDIT_NULL_ARG)
  {
    return make_array(
      "code", 1,
      1, "Audit template $1$ was passed a NULL value."
    );
  }
  else if (audit_id == AUDIT_AUDIT_ARRAY_ARG)
  {
    return make_array(
      "code", 1,
      2, "Audit template $1$ was passed an array value: $2$."
    );
  }
  else
    return NULL;
}

##
# Exits using a template for the audit message.
#
# @param id   Specifies which audit configuration to use.
#
# @param code Specifies the exit code, default is taken from the audit
#             configuration for the passed ID.
#
# @remark To prevent parameters from adding replacements and causing
#         problems, anything of the form $[0-9]+$ will be replaced
#         with ${[0-9]+}$.
#
# @return Does not ever return, always exits.
##
function audit(code)
{
  local_var arg, cfg, i, j, item, info, arg_len, id, max, msg, list_arg, key;

  # Sanity check parameters.
  max = max_index(_FCT_ANON_ARGS);
  if (max == 0)
    audit(AUDIT_AUDIT_MISSING);
  max--;

  # Extract audit ID.
  id = _FCT_ANON_ARGS[0];

  # Get audit configuration.
  cfg = get_audit_message(id);
  if (isnull(cfg))
    audit(AUDIT_AUDIT_UNKNOWN, id);

  # Take code from configuration if not explicitly given by caller.
  if (isnull(code))
  {
    code = cfg["code"];

    if (isnull(code))
      audit(AUDIT_AUDIT_CODE_MISSING, id);
  }

  # Special case for AUDIT_ACTIVEX
  # Switch to another template if ActiveX version is unknown
  if(id == AUDIT_ACTIVEX && max == 1 &&
     tolower(_FCT_ANON_ARGS[1]) == "unknown")
    max = 0;

  # Get format string.
  msg = cfg[max];
  if (isnull(msg))
    audit(AUDIT_AUDIT_MISMATCH, max, id);

  # Stick the passed values into the format string.
  for (i = 1; i <= max; i++)
  {
    arg = _FCT_ANON_ARGS[i];
    if (isnull(arg))
      audit(AUDIT_AUDIT_NULL_ARG, id);
    else if(typeof(arg) == 'array')
    {
      # handle multiple installed versions in audit (passed in a list)
      if(i == 2 && id == AUDIT_INST_VER_NOT_VULN)
      {
        arg_len = max_index(arg);
        j = 0;
        info = '';
        # handle multiple non-affected versions :
        # 1   - 1.2.3
        # > 1 - 1.2.3 and 1.2.4
        # > 2 - 1.2.3, 1.2.4, and 1.2.5
        foreach item (arg)
        {
          if(typeof(item) == 'array')
            exit(1, 'Unexpected nested array in AUDIT_INST_VER_NOT_VULN version list.');
          if(arg_len == 1 || (arg_len == 2 && j == 0)) info += item;
          else if(arg_len > 2 && j != (arg_len - 1)) info += item + ', ';
          else if(arg_len > 2 && j == (arg_len - 1)) info += 'and ' + item;
          else if(arg_len == 2 && j == 1) info += ' and ' + item;
          j++;
        }
        arg = info;
        if(arg_len > 1) # re-work format string for multiple versions
        {
          msg = ereg_replace(string:msg, pattern:" is ", replace:" are ");
          msg = ereg_replace(string:msg, pattern:" version ", replace:" versions ");
        }
      }
      else
      {
        list_arg = '[ ';
        foreach key (keys(arg))
          list_arg += key + ' => ' + arg[key] + ', ';
        list_arg = substr(list_arg, 0, strlen(list_arg) - 3);
        list_arg += ' ]';

        audit(AUDIT_AUDIT_ARRAY_ARG, id, list_arg);
      }
    }

    arg = ereg_replace(string:arg, pattern:"\$([0-9]+)\$", replace:"\${\1}\$");
    msg = ereg_replace(string:msg, pattern:"\$" + i + "\$", replace:arg);
  }

  # Special cases.
  #
  # - AUDIT_PACKAGE_NOT_INSTALLED / AUDIT_PACKAGE_NOT_AFFECTED
  if (
    (
      id == AUDIT_PACKAGE_NOT_INSTALLED ||
      id == AUDIT_PACKAGE_NOT_AFFECTED
    ) &&
    " " >< _FCT_ANON_ARGS[1]
  ) msg = str_replace(find:"package is", replace:"packages are", string:msg);

  exit(code, msg);
}
