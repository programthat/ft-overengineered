import { GuiService } from "@rbxts/services";
import { SoundController } from "client/controller/SoundController";
import { ButtonControl } from "engine/client/gui/Button";
import { Control } from "engine/client/gui/Control";
import { Interface } from "engine/client/gui/Interface";
import type { ReportSubmitPopupDefinition } from "client/gui/popup/ReportSubmitPopup";

export class TextCopyPopup extends Control<ReportSubmitPopupDefinition> {
	constructor(data: string, text: string, title?: string, okFunc?: () => void) {
		const gui = Interface.getInterface<{
			Popups: { Crossplatform: { ReportSubmit: ReportSubmitPopupDefinition } };
		}>().Popups.Crossplatform.ReportSubmit.Clone();
		super(gui);

		const okButton = this.parent(new Control(gui.Content.Buttons.OkButton));
		okButton.addButtonAction(() => {
			okFunc?.();
			this.hideThenDestroy();
		});
		this.event.onPrepareGamepad(() => (GuiService.SelectedObject = okButton.instance));

		this.parent(new ButtonControl(gui.Heading.CloseButton, () => this.hideThenDestroy()));

		this.onEnable(() => SoundController.getUISounds().Start.Play());

		gui.Content.Text.Text = text;
		gui.Heading.TitleLabel.Text = title ?? "COPY TEXT";
		gui.Content.TextBox.Text = data;
	}
}
