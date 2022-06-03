unit Firewall;

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections,ActiveX,ComObj,
  System.Variants,Winapi.ShellAPI,system.strutils;

type TRegras=class
  Nome:string;
  Descricao:string;
  NomeAplicacao:string;
  NomeDoServico:string;
  IPProtoloco:string;
  PortaLocal:string;
  PortaRemota:string;
  EnderecoLocal:string;
  EnderecoRemoto:string;
  Direcao:string;
  Enable:string;
  Edge:string;
  Acao:string;
  Grouping:string;
  InterfaceType:string;
  DescricaoFirewalAtivo:string;
  ICMP:STRING;
end;

type TRetorno = record
     Mensagem:string;
end;

type
  DTFirewall = class(TComponent)
  private
    { Private declarations }
  protected
    { Protected declarations }
  public
    Lista:TList<TRegras>;
    Retorno:TRetorno;
    Function ListarRegrasDoFirewall:TRegras;
    Procedure DesabilitarFirewall;
    Procedure HabilitarFirewall;
    Procedure ObtemStatusDoFirewall;
    Function AdicionaRegrasDeProtocolo(NomeDaRegra:string;DescricaoDaRegra:string;Protocolo:Integer;Enable:Boolean):TRetorno;
    function AdicionaRegrasDeAplicacao(NomeDaRegra:string;DescricaoDaRegra:string;CaminhoDaAplicacao:string;Grouping:string;Enable:Boolean):TRetorno;
    Function AdicionaRegrasDePorta(NomeDaRegra : String; Porta : Cardinal;  Permite : Boolean = True):TRetorno;
    Function VerificaSeRegraEstaArtiva(Nome:string):Boolean;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  published
    { Published declarations }
  end;

procedure Register;

implementation

uses
  Winapi.Windows;

procedure Register;
begin
  RegisterComponents('DT Inovacao', [DTFirewall]);
end;

{ DTFirewall }

Function DTFirewall.AdicionaRegrasDeAplicacao(NomeDaRegra:string;DescricaoDaRegra:string;CaminhoDaAplicacao:string;Grouping:string;Enable:Boolean):TRetorno;
Const
 NET_FW_ACTION_ALLOW    = 1;
 NET_FW_IP_PROTOCOL_TCP = 6;
var
 CurrentProfiles : OleVariant;
 fwPolicy2       : OleVariant;
 RulesObject     : OleVariant;
 NewRule         : OleVariant;
begin
    try
          try
                fwPolicy2       := CreateOleObject('HNetCfg.FwPolicy2');
                RulesObject     := fwPolicy2.Rules;
                CurrentProfiles := fwPolicy2.CurrentProfileTypes;

                NewRule         := CreateOleObject('HNetCfg.FWRule');

                NewRule.Name            := NomeDaRegra;
                NewRule.Description     := DescricaoDaRegra;
                NewRule.Applicationname := CaminhoDaAplicacao;
                NewRule.Protocol        := NET_FW_IP_PROTOCOL_TCP;
                NewRule.LocalPorts      := 4000;
                NewRule.Enabled         := Enable;
                NewRule.Grouping        := Grouping;
                NewRule.Profiles        := CurrentProfiles;
                NewRule.Action          := NET_FW_ACTION_ALLOW;

                RulesObject.Add(NewRule);
                retorno.Mensagem := 'Regra de Aplicacao Criada com sucesso';
          except on e:Exception do
              begin
                  retorno.Mensagem := e.Message;
              end;
          end;
    finally

    end;
end;

Function DTFirewall.AdicionaRegrasDePorta(NomeDaRegra: String; Porta: Cardinal;
  Permite: Boolean):TRetorno;
var
Handle:Cardinal;
begin
    ShellExecute(Handle, nil, 'netsh.exe',
    PChar(
    'advfirewall firewall add rule name = "' + NomeDaRegra +'" dir = in action = '+
    IfThen(Permite, 'allow', 'block') + ' protocol = any'),nil, SW_HIDE);

    {ShellExecute(Handle, nil, 'netsh.exe',
    PChar(
    'advfirewall firewall add rule name = "' + NomeDaRegra +'" dir = in action = '+
    IfThen(Permite, 'allow', 'block') +' protocol = TCP localport = ' +
    IntToStr(Porta)),nil, SW_HIDE);}

    Retorno.Mensagem := 'Regra de Porta adicionada com sucesso';
end;

Function DTFirewall.AdicionaRegrasDeProtocolo(NomeDaRegra:string;DescricaoDaRegra:string;Protocolo:Integer;Enable:Boolean):TRetorno;
Const
NET_FW_ACTION_ALLOW = 1;
var
CurrentProfiles : OleVariant;
fwPolicy2       : OleVariant;
RulesObject     : OleVariant;
NewRule         : OleVariant;
begin
 try
    try
      fwPolicy2           := CreateOleObject('HNetCfg.FwPolicy2');
      RulesObject         := fwPolicy2.Rules;
      CurrentProfiles     := fwPolicy2.CurrentProfileTypes;

      NewRule             := CreateOleObject('HNetCfg.FWRule');

      NewRule.Name        := NomeDaRegra;
      NewRule.Description := DescricaoDaRegra;
      NewRule.Protocol    := Protocolo;
      NewRule.Enabled     := Enable;
      NewRule.Profiles    := CurrentProfiles;
      NewRule.Action      := NET_FW_ACTION_ALLOW;

      RulesObject.Add(NewRule);
      Retorno.Mensagem := 'Regra de protocolo adicionada com sucesso';
    except on e:Exception do
    begin
         retorno.Mensagem := e.Message;
    end;
    end;
 finally

 end;
end;

constructor DTFirewall.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  Lista    := TList<TRegras>.Create;
end;

procedure DTFirewall.DesabilitarFirewall;
Const
  NET_FW_PROFILE2_DOMAIN  = 1;
  NET_FW_PROFILE2_PRIVATE = 2;
  NET_FW_PROFILE2_PUBLIC  = 4;
var
 fwPolicy2 : OleVariant;
begin
   try
      try
        fwPolicy2   := CreateOleObject('HNetCfg.FwPolicy2');

        fwPolicy2.FirewallEnabled[NET_FW_PROFILE2_DOMAIN] := False;
        fwPolicy2.FirewallEnabled[NET_FW_PROFILE2_PRIVATE]:= False;
        fwPolicy2.FirewallEnabled[NET_FW_PROFILE2_PUBLIC] := False;
        Retorno.Mensagem := 'Firewall Desativado';
      except on e:Exception do
      begin
            retorno.Mensagem := e.Message;
      end;
      end;
   finally

   end;
end;

destructor DTFirewall.Destroy;
begin
     Lista.Clear;

     FreeAndNil(Lista);

  inherited Destroy;
end;

procedure DTFirewall.HabilitarFirewall;
Const
  NET_FW_PROFILE2_DOMAIN  = 1;
  NET_FW_PROFILE2_PRIVATE = 2;
  NET_FW_PROFILE2_PUBLIC  = 4;
var
 fwPolicy2 : OleVariant;
begin
      try
        try
          fwPolicy2   := CreateOleObject('HNetCfg.FwPolicy2');

          fwPolicy2.FirewallEnabled[NET_FW_PROFILE2_DOMAIN] := True;
          fwPolicy2.FirewallEnabled[NET_FW_PROFILE2_PRIVATE]:= True;
          fwPolicy2.FirewallEnabled[NET_FW_PROFILE2_PUBLIC] := True;
          Retorno.Mensagem := 'Firewall Habilitado';
        except on e:Exception do
            begin
                  retorno.Mensagem := e.Message;
            end;
        end;
      finally

      end;
end;

Function DTFirewall.ListarRegrasDoFirewall:TRegras;
Const
  NET_FW_PROFILE2_DOMAIN    = 1;
  NET_FW_PROFILE2_PRIVATE   = 2;
  NET_FW_PROFILE2_PUBLIC    = 4;

  NET_FW_IP_PROTOCOL_TCP    = 6;
  NET_FW_IP_PROTOCOL_UDP    = 17;
  NET_FW_IP_PROTOCOL_ICMPv4 = 1;
  NET_FW_IP_PROTOCOL_ICMPv6 = 58;

  NET_FW_RULE_DIR_IN        = 1;
  NET_FW_RULE_DIR_OUT       = 2;

  NET_FW_ACTION_BLOCK       = 0;
  NET_FW_ACTION_ALLOW       = 1;
var
 CurrentProfiles : Integer;
 fwPolicy2       : OleVariant;
 RulesObject     : OleVariant;
 rule            : OleVariant;
 oEnum           : IEnumvariant;
 iValue          : LongWord;
 Lst:TRegras;
begin
   try
        try
          lst             := TRegras.Create;
          fwPolicy2       := CreateOleObject('HNetCfg.FwPolicy2');
          RulesObject     := fwPolicy2.Rules;
          CurrentProfiles := fwPolicy2.CurrentProfileTypes;

          oEnum := IUnknown(Rulesobject._NewEnum) as IEnumVariant;
          while oEnum.Next(1, rule, iValue) = 0 do
          begin
            if (CurrentProfiles AND NET_FW_PROFILE2_DOMAIN)<>0 then
              Lst.DescricaoFirewalAtivo := 'Domain Firewall Profile is active';

            if ( CurrentProfiles AND NET_FW_PROFILE2_PRIVATE )<>0 then
                Lst.DescricaoFirewalAtivo := 'Private Firewall Profile is active';

            if ( CurrentProfiles AND NET_FW_PROFILE2_PUBLIC )<>0 then
                Lst.DescricaoFirewalAtivo := 'Public Firewall Profile is active';

            if (rule.Profiles And CurrentProfiles)<>0 then
            begin
                Lst.Nome          := rule.Name;
                Lst.Descricao     := rule.Description;
                Lst.NomeAplicacao := rule.ApplicationName;
                Lst.NomeDoServico := rule.ServiceName;

                Case rule.Protocol of
                   NET_FW_IP_PROTOCOL_TCP    : Lst.IPProtoloco := 'TCP';
                   NET_FW_IP_PROTOCOL_UDP    : Lst.IPProtoloco := 'UDP';
                   NET_FW_IP_PROTOCOL_ICMPv4 : Lst.IPProtoloco := 'UDP';
                   NET_FW_IP_PROTOCOL_ICMPv6 : Lst.IPProtoloco := 'UDP';
                Else                           Lst.IPProtoloco := VarToStr(rule.Protocol);
                End;

                if (rule.Protocol = NET_FW_IP_PROTOCOL_TCP) or (rule.Protocol = NET_FW_IP_PROTOCOL_UDP) then
                begin
                  LST.PortaLocal     := rule.LocalPorts;
                  LST.PortaRemota    := rule.RemotePorts;
                  LST.EnderecoLocal  := rule.LocalAddresses;
                  LST.EnderecoRemoto := rule.RemoteAddresses;
                end;

                if (rule.Protocol = NET_FW_IP_PROTOCOL_ICMPv4) or (rule.Protocol = NET_FW_IP_PROTOCOL_ICMPv6) then
                 Lst.ICMP := rule.IcmpTypesAndCodes;

                Case rule.Direction of
                    NET_FW_RULE_DIR_IN :  LST.Direcao := 'In';
                    NET_FW_RULE_DIR_OUT:  LST.Direcao := 'Out';
                End;

                LST.Enable := VarToStr(rule.Enabled);
                LST.Edge   := VarToStr(rule.EdgeTraversal);

                Case rule.Action of
                   NET_FW_ACTION_ALLOW : LST.Acao := 'Allow';
                   NET_FW_ACTION_BLOCk : LST.Acao := 'Block';
                End;

                Lst.Grouping      := rule.Grouping;
                Lst.Edge          := VarToStr(rule.EdgeTraversal);
                Lst.InterfaceType := rule.InterfaceTypes;

                Lista.Add(Lst);
            end;
            rule:=Unassigned;
          end;
        except on e:Exception do
             begin
                 retorno.Mensagem := e.Message;
             end;
        end;
   finally

   end;
end;

procedure DTFirewall.ObtemStatusDoFirewall;
const
  NET_FW_PROFILE2_DOMAIN  = 1;
  NET_FW_PROFILE2_PRIVATE = 2;
  NET_FW_PROFILE2_PUBLIC  = 4;
var
 CurrentProfiles : Integer;
 fwPolicy2       : OleVariant;
begin
    try
        try
            fwPolicy2   := CreateOleObject('HNetCfg.FwPolicy2');
            CurrentProfiles := fwPolicy2.CurrentProfileTypes;

            if (CurrentProfiles AND NET_FW_PROFILE2_DOMAIN)<>0 then
               if fwPolicy2.FirewallEnabled[NET_FW_PROFILE2_DOMAIN] then
                 Retorno.Mensagem := 'Firewall is ON on domain profile.'
               else
                 Retorno.Mensagem := 'Firewall is OFF on domain profile.';

            if (CurrentProfiles AND NET_FW_PROFILE2_PRIVATE)<>0 then
               if fwPolicy2.FirewallEnabled[NET_FW_PROFILE2_PRIVATE] then
                 Retorno.Mensagem := 'Firewall is ON on private profile.'
               else
                 Retorno.Mensagem := 'Firewall is OFF on private profile.';

            if (CurrentProfiles AND NET_FW_PROFILE2_PUBLIC)<>0 then
               if fwPolicy2.FirewallEnabled[NET_FW_PROFILE2_PUBLIC] then
                 Retorno.Mensagem := 'Firewall is ON on public profile.'
               else
                 Retorno.Mensagem := 'Firewall is OFF on public profile.';
        except on e:Exception do
           begin
               retorno.Mensagem := e.Message;
           end;
        end;
    finally

    end;
end;

function DTFirewall.VerificaSeRegraEstaArtiva(Nome:string): Boolean;
Const
  NET_FW_PROFILE2_DOMAIN    = 1;
  NET_FW_PROFILE2_PRIVATE   = 2;
  NET_FW_PROFILE2_PUBLIC    = 4;

  NET_FW_IP_PROTOCOL_TCP    = 6;
  NET_FW_IP_PROTOCOL_UDP    = 17;
  NET_FW_IP_PROTOCOL_ICMPv4 = 1;
  NET_FW_IP_PROTOCOL_ICMPv6 = 58;

  NET_FW_RULE_DIR_IN        = 1;
  NET_FW_RULE_DIR_OUT       = 2;

  NET_FW_ACTION_BLOCK       = 0;
  NET_FW_ACTION_ALLOW       = 1;
var
 CurrentProfiles : Integer;
 fwPolicy2       : OleVariant;
 RulesObject     : OleVariant;
 rule            : OleVariant;
 oEnum           : IEnumvariant;
 iValue          : LongWord;
begin
 try
     try
          result          := false;
          fwPolicy2       := CreateOleObject('HNetCfg.FwPolicy2');
          RulesObject     := fwPolicy2.Rules;
          CurrentProfiles := fwPolicy2.CurrentProfileTypes;

          oEnum := IUnknown(Rulesobject._NewEnum) as IEnumVariant;
          while oEnum.Next(1, rule, iValue) = 0 do
          begin
            if (rule.Profiles And CurrentProfiles)<>0 then
            begin
                if UpperCase(Nome) = UpperCase(rule.Name) then
                begin
                     Result := True;
                end;
            end;
            rule:=Unassigned;
          end;

          if Result=True then
          begin
                retorno.Mensagem := 'Regra existe';
          end else begin
                retorno.Mensagem := 'Regra não existe';
          end;
     except on e:Exception do
     begin
         retorno.Mensagem := e.Message;
     end;
     end;
 finally

 end;
end;

end.
