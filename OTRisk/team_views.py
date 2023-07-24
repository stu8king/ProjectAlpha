from django.shortcuts import render, redirect
from django.forms import formset_factory
from OTRisk.forms import TeamMemberForm
from OTRisk.models.TeamMember import TeamMember


def add_team_members(request):
    TeamMemberFormSet = formset_factory(TeamMemberForm, extra=5)  # Adjust extra as needed

    if request.method == 'POST':
        formset = TeamMemberFormSet(request.POST)
        if formset.is_valid():
            risk_id = request.session.get('post_id')
            if risk_id:
                team_members_data = []

                for form in formset:
                    first_name = form.cleaned_data.get('first_name')
                    last_name = form.cleaned_data.get('last_name')
                    title = form.cleaned_data.get('title')
                    organization = form.cleaned_data.get('organization')
                    department = form.cleaned_data.get('department')
                    notes = form.cleaned_data.get('notes')

                    if not first_name or not last_name or not title or not organization or not department:
                        break

                    team_member_data = {
                        'FirstName': first_name,
                        'LastName': last_name,
                        'Title': title,
                        'Organization': organization,
                        'Department': department,
                        'Notes': notes,
                        'RiskID': risk_id
                    }
                    team_members_data.append(team_member_data)

                if team_members_data:
                    TeamMember.objects.bulk_create([TeamMember(**data) for data in team_members_data])

                return redirect('OTRisk:post_create')
    else:
        formset = TeamMemberFormSet()

    context = {'formset': formset}
    return render(request, 'OTRisk/team_member.html', context)

