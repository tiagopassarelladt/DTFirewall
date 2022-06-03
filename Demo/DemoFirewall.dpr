program DemoFirewall;

uses
  Vcl.Forms,
  Demo in 'Demo.pas' {Form5},
  Vcl.Themes,
  Vcl.Styles;

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  TStyleManager.TrySetStyle('Auric');
  Application.CreateForm(TForm5, Form5);
  Application.Run;
end.
