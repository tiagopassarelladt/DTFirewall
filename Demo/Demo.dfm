object Form5: TForm5
  Left = 0
  Top = 0
  BorderIcons = [biSystemMenu]
  BorderStyle = bsSingle
  Caption = 'Demo Firewall'
  ClientHeight = 462
  ClientWidth = 767
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object Memo1: TMemo
    Left = 0
    Top = 70
    Width = 767
    Height = 392
    Align = alBottom
    Lines.Strings = (
      'Memo1')
    ScrollBars = ssVertical
    TabOrder = 0
  end
  object Button1: TButton
    Left = 8
    Top = 8
    Width = 121
    Height = 25
    Cursor = crHandPoint
    Caption = 'Status do Firewall'
    TabOrder = 1
    OnClick = Button1Click
  end
  object Button2: TButton
    Left = 135
    Top = 8
    Width = 154
    Height = 25
    Cursor = crHandPoint
    Caption = 'Lista de Regras do Firewall'
    TabOrder = 2
    OnClick = Button2Click
  end
  object Button3: TButton
    Left = 295
    Top = 8
    Width = 138
    Height = 25
    Cursor = crHandPoint
    Caption = 'Desabilita Firewall'
    TabOrder = 3
    OnClick = Button3Click
  end
  object Button4: TButton
    Left = 439
    Top = 8
    Width = 161
    Height = 25
    Cursor = crHandPoint
    Caption = 'Adicionar Regra de Aplicativo'
    TabOrder = 4
    OnClick = Button4Click
  end
  object Button5: TButton
    Left = 606
    Top = 8
    Width = 146
    Height = 25
    Cursor = crHandPoint
    Caption = 'Adicionar Regra de Porta'
    TabOrder = 5
    OnClick = Button5Click
  end
  object Button6: TButton
    Left = 8
    Top = 39
    Width = 121
    Height = 25
    Cursor = crHandPoint
    Caption = 'Habilitar Firewall'
    TabOrder = 6
    OnClick = Button6Click
  end
  object Button7: TButton
    Left = 135
    Top = 39
    Width = 154
    Height = 25
    Cursor = crHandPoint
    Caption = 'Verificar se Regra Existe'
    TabOrder = 7
    OnClick = Button7Click
  end
  object DTFirewall1: DTFirewall
    Left = 352
    Top = 80
  end
end
