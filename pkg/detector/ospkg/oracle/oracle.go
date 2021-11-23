package oracle

import (
	"strings"
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	ftypes "github.com/aquasecurity/fanal/types"
	oracleoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/oracle-oval"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		// Source:
		// https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf
		// https://community.oracle.com/docs/DOC-917964
		"3": time.Date(2011, 12, 31, 23, 59, 59, 0, time.UTC),
		"4": time.Date(2013, 12, 31, 23, 59, 59, 0, time.UTC),
		"5": time.Date(2017, 12, 31, 23, 59, 59, 0, time.UTC),
		"6": time.Date(2021, 3, 21, 23, 59, 59, 0, time.UTC),
		"7": time.Date(2024, 7, 23, 23, 59, 59, 0, time.UTC),
		"8": time.Date(2029, 7, 18, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements oracle vulnerability scanner
type Scanner struct {
	vs    oracleoval.VulnSrc
	clock clock.Clock
}

// NewScanner is the factory method to return oracle vulnerabilities
func NewScanner() *Scanner {
	return &Scanner{
		vs:    oracleoval.NewVulnSrc(),
		clock: clock.RealClock{},
	}
}

func extractKsplice(v string) string {
	subs := strings.Split(strings.ToLower(v), ".")
	for _, s := range subs {
		if strings.HasPrefix(s, "ksplice") {
			return s
		}
	}
	return ""
}

func isTrackedPackage(packName string) bool  {
	m := map[string]bool {
		"bind-export-libs": true,
		"curl": true,
		"dnf": true,
		"dnf-data": true,
		"dnf-plugins-core": true,
		"file-libs": true,
		"glib2": true,
		"glibc": true,
		"glibc-common": true,
		"glibc-langpack-en": true,
		"gnutls": true,
		"json-c": true,
		"libcurl": true,
		"libdnf": true,
		"libgcc": true,
		"libgcrypt": true,
		"libsepol": true,
		"libsolv": true,
		"libssh": true,
		"libssh-config": true,
		"libstdc++": true,
		"lua-libs": true,
		"ncurses": true,
		"ncurses-base": true,
		"ncurses-libs": true,
		"nettle": true,
		"openssh": true,
		"openssh-clients": true,
		"openssh-server": true,
		"openssl-libs": true,
		"pcre": true,
		"platform-python": true,
		"python3-dnf": true,
		"python3-dnf-plugins-core": true,
		"python3-hawkey": true,
		"python3-libdnf": true,
		"python3-libs": true,
		"python3-pip-wheel": true,
		"python3-rpm": true,
		"rpm": true,
		"rpm-build-libs": true,
		"rpm-libs": true,
		"sqlite-libs": true,
		"vim-minimal": true,
		"yum": true,
		"yum-utils": true,
	}
	if _, ok := m[packName]; ok {
		return true
	}
	return false
}

// Detect scans and return vulnerability in Oracle scanner
func (s *Scanner) Detect(osVer string, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting Oracle Linux vulnerabilities...")
	basicVer := osVer

	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}

	log.Logger.Debugf("Oracle Linux: os version: %s", osVer)
	log.Logger.Debugf("Oracle Linux: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(osVer, pkg.Name)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Oracle Linux advisory: %w", err)
		}
		installed := utils.FormatVersion(pkg)
		installedVersion := version.NewVersion(installed)

		tracked := isTrackedPackage(pkg.Name)
		if tracked && pkg.Name == "glibc"{
			log.Logger.Debug("----------------------------------------------------------------------------------")
			log.Logger.Debugf("[Tracking] OS version: %s. Package %q, installedVersion: %s-%s",
				basicVer, pkg.Name, pkg.SrcVersion, pkg.SrcRelease)
		}

		for _, adv := range advisories {
			if tracked && pkg.Name == "glibc" {
				log.Logger.Debugf("[Tracking] %q, FixedVersion: %q", adv.VulnerabilityID, adv.FixedVersion)
			}

			// when one of them doesn't have ksplice, we'll also skip it
			// extract kspliceX and compare it with kspliceY in advisories
			// if kspliceX and kspliceY are different, we will skip the advisory
			if extractKsplice(adv.FixedVersion) != extractKsplice(pkg.Release) {
				continue
			}

			fixedVersion := version.NewVersion(adv.FixedVersion)
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
				Layer:            pkg.Layer,
				Custom:           adv.Custom,
			}
			if installedVersion.LessThan(fixedVersion) {
				vuln.FixedVersion = adv.FixedVersion
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

// IsSupportedVersion checks is OSFamily can be scanned with Oracle scanner
func (s *Scanner) IsSupportedVersion(osFamily, osVer string) bool {
	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}

	eol, ok := eolDates[osVer]
	if !ok {
		log.Logger.Warnf("This OS version is not on the EOL list: %s %s", osFamily, osVer)
		return false
	}

	return s.clock.Now().Before(eol)
}
