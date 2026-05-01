package models

type ProjectContext struct {
	RootPath          string
	LaravelVersion    string
	PHPVersion        string
	ProjectName       string
	FrameworkType     string
	FrameworkVersion  string
	ComposerDeps      map[string]string
	InstalledPackages []Package
	EnvVariables      map[string]string
	ConfigFiles       []string
}
type Package struct {
	Name      string
	Version   string
	Ecosystem string
	File      string
}
