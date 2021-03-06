unit Demo;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Firewall;

type
  TForm5 = class(TForm)
    DTFirewall1: DTFirewall;
    Memo1: TMemo;
    Button1: TButton;
    Button2: TButton;
    Button3: TButton;
    Button4: TButton;
    Button5: TButton;
    Button6: TButton;
    Button7: TButton;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
    procedure Button5Click(Sender: TObject);
    procedure Button6Click(Sender: TObject);
    procedure Button7Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form5: TForm5;

implementation

{$R *.dfm}

procedure TForm5.Button1Click(Sender: TObject);
begin
     DTFirewall1.ObtemStatusDoFirewall;

     Memo1.Lines.Clear;
     Memo1.Lines.Add(DTFirewall1.Retorno.Mensagem);
end;

procedure TForm5.Button2Click(Sender: TObject);
var
i:Integer;
begin
     DTFirewall1.ListarRegrasDoFirewall;

     for I := 0 to Pred(DTFirewall1.Lista.Count) do
       begin
             Memo1.Lines.Add('Nome: ' + DTFirewall1.Lista[i].Nome);
             Memo1.Lines.Add('Descricao: ' + DTFirewall1.Lista[i].Descricao);
             Memo1.Lines.Add('NomeAplicacao: ' + DTFirewall1.Lista[i].NomeAplicacao);
             Memo1.Lines.Add('NomeDoServico: ' + DTFirewall1.Lista[i].NomeDoServico);
             Memo1.Lines.Add('IPProtoloco: ' + DTFirewall1.Lista[i].IPProtoloco);
             Memo1.Lines.Add('PortaLocal: ' + DTFirewall1.Lista[i].PortaLocal);
             Memo1.Lines.Add('PortaRemota: ' + DTFirewall1.Lista[i].PortaRemota);
             Memo1.Lines.Add('EnderecoLocal: ' + DTFirewall1.Lista[i].EnderecoLocal);
             Memo1.Lines.Add('EnderecoRemoto: ' + DTFirewall1.Lista[i].EnderecoRemoto);
             Memo1.Lines.Add('Direcao: ' + DTFirewall1.Lista[i].Direcao);
             Memo1.Lines.Add('Enable: ' + DTFirewall1.Lista[i].Enable);
             Memo1.Lines.Add('Edge: ' + DTFirewall1.Lista[i].Edge);
             Memo1.Lines.Add('Acao: ' + DTFirewall1.Lista[i].Acao);
             Memo1.Lines.Add('Grouping: ' + DTFirewall1.Lista[i].Grouping);
             Memo1.Lines.Add('InterfaceType: ' + DTFirewall1.Lista[i].InterfaceType);
             Memo1.Lines.Add('DescricaoFirewalAtivo: ' + DTFirewall1.Lista[i].DescricaoFirewalAtivo);
             Memo1.Lines.Add('ICMP: ' + DTFirewall1.Lista[i].ICMP);

             Memo1.Lines.Add('===================================');
       end;
       Memo1.Lines.Add('Total de Regras: ' + DTFirewall1.Lista.Count.ToString);
end;

procedure TForm5.Button3Click(Sender: TObject);
begin
    DTFirewall1.DesabilitarFirewall;
    Memo1.Lines.Clear;
    Memo1.Lines.Add(DTFirewall1.Retorno.Mensagem);
end;

procedure TForm5.Button4Click(Sender: TObject);
begin
    DTFirewall1.AdicionaRegrasDeAplicacao('PASSARELLA','APENAS UM TESTE DE UMA REGRA PELO COMPONENTE','C:\SUPERSYS10\SUPERSYS.EXE','PASSARELLA',True);
    Memo1.Lines.Clear;
    Memo1.Lines.Add(DTFirewall1.Retorno.Mensagem);
end;

procedure TForm5.Button5Click(Sender: TObject);
begin
     DTFirewall1.AdicionaRegrasDePorta('FIREBIRD',3050,True);
     Memo1.Lines.Clear;
     Memo1.Lines.Add(DTFirewall1.Retorno.Mensagem);
end;

procedure TForm5.Button6Click(Sender: TObject);
begin
      DTFirewall1.HabilitarFirewall;
      Memo1.Lines.Clear;
      Memo1.Lines.Add(DTFirewall1.Retorno.Mensagem);
end;

procedure TForm5.Button7Click(Sender: TObject);
begin
     DTFirewall1.VerificaSeRegraEstaArtiva('passarella');
     Memo1.Lines.Clear;
     Memo1.Lines.Add('Regra Passarella: ' + DTFirewall1.Retorno.Mensagem);

     DTFirewall1.VerificaSeRegraEstaArtiva('Firebird');
     Memo1.Lines.Add('Regra Firebird: ' + DTFirewall1.Retorno.Mensagem);
end;

end.
