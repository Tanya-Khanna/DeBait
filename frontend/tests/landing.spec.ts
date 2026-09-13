import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.route('**/api/usage', route => route.fulfill({json:null}));
});

test('landing exposes a clear local entry and honest evaluation status', async ({ page }) => {
  await page.goto('/');

  await expect(page.getByRole('heading', { name: 'Scammers cross apps. DeBait does too.' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open protection workspace' })).toHaveAttribute('href', '/app');
  await expect(page.getByRole('link', { name: 'View evaluation approach' })).toHaveAttribute('href', '/evaluations');
  await expect(page.getByRole('link', { name: 'Explore system architecture' })).toHaveAttribute('href', '/architecture');
  await expect(page.getByText('Evaluation not run.', { exact: true })).toBeVisible();
  await expect(page.getByText('Illustrative sequence', { exact: true })).toBeVisible();
});

test('landing keeps its core content usable on a narrow viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');

  await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'One episode. Four surfaces. One precise response.' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'See every step from signal to stronger policy.' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Designed for controlled environments.' })).toBeVisible();
});

test('workspace reports backend connection state without inventing data', async ({ page }) => {
  await page.route('**/api/episodes', (route) => route.abort('failed'));
  await page.goto('/app');

  await expect(page.getByRole('heading', { name: 'Protection workspace' })).toBeVisible();
  await expect(page.getByText('Backend unavailable')).toBeVisible();
});

test('workspace offers local session unlock when the backend requires authorization', async ({ page }) => {
  await page.route('**/api/episodes', (route) => route.fulfill({ status: 401, json: { detail: 'Unauthorized' } }));
  await page.goto('/app');

  await expect(page.getByRole('heading', { name: 'Local session locked' })).toBeVisible();
  await expect(page.getByLabel('Local operator token')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Unlock workspace' })).toBeVisible();
});

test('evaluation route is explicit when no run exists', async ({ page }) => {
  await page.route('**/api/evaluations', route => route.fulfill({json:[]}));
  await page.goto('/evaluations');

  await expect(page.getByRole('heading', { name: 'Evaluation not run.' })).toBeVisible();
  await expect(page.getByText(/No measured results are available/)).toBeVisible();
});

test('evaluation route renders measured fixture denominators and limits', async ({ page }) => {
  await page.route('**/api/evaluations', route => route.fulfill({json:[{
    run_id:'eval-1', run_mode:'local_fixture', reasoning_mode:'deterministic_fixture',
    created_at:'2026-09-13T12:00:00Z', repeats:3,
    metrics:{unique_case_count:5,total_runs:15,attack_count:12,attacks_contained:9,
      recoverable_attack_count:9,recoverable_attacks_contained:9,
      benign_count:3,benign_uninterrupted:3,false_financial_interventions:0,
      unauthorized_effects:0,duplicate_logical_effects:0,incorrect_final_states:0,
      median_containment_seconds:0.18,p95_containment_seconds:0.22},
    limitations:['Synthetic stateful world; no live provider action is measured.']
  }]}));
  await page.goto('/evaluations');
  await expect(page.getByRole('heading',{name:'Local reliability baseline'})).toBeVisible();
  await expect(page.getByText('15',{exact:true})).toBeVisible();
  await expect(page.getByText(/no live provider action/i)).toBeVisible();
});

test('evaluation route surfaces campaign outcome accuracy and honest fault context', async ({ page }) => {
  await page.route('**/api/evaluations', route => route.fulfill({json:[{
    run_id:'campaign-1', run_mode:'local_fixture', reasoning_mode:'deterministic_fixture',
    created_at:'2026-09-13T12:00:00Z', repeats:3,
    metrics:{unique_case_count:48,total_runs:144,correct_outcomes:144,outcome_accuracy:1.0,
      attack_count:108,attacks_contained:84,missed_attacks:24,recoverable_attack_count:84,
      recoverable_attacks_contained:84,fault_cases:36,fault_outcomes_correct:36,
      benign_count:36,benign_uninterrupted:36,false_financial_interventions:0,
      unauthorized_effects:0,duplicate_logical_effects:0,incorrect_final_states:0,
      median_containment_seconds:0.2,p95_containment_seconds:0.37},
    limitations:['Synthetic stateful world; no live provider action is measured.']
  }]}));
  await page.goto('/evaluations');
  await expect(page.getByTestId('correct-outcomes')).toContainText('144 / 144');
  await expect(page.getByTestId('correct-outcomes')).toContainText('100%');
  await expect(page.getByTestId('fault-note')).toContainText(/prevention-failed/);
  await expect(page.getByText('84 / 84')).toBeVisible();
});

test('evaluation route flags a live-model run and its measured cost', async ({ page }) => {
  await page.route('**/api/evaluations', route => route.fulfill({json:[{
    run_id:'fresh-1', run_mode:'local_fresh_model', reasoning_mode:'fresh_model:gpt-5.6-luna',
    created_at:'2026-09-13T18:00:00Z', repeats:1,
    metrics:{unique_case_count:48,total_runs:48,correct_outcomes:46,outcome_accuracy:0.9583,
      attack_count:36,attacks_contained:28,recoverable_attack_count:28,recoverable_attacks_contained:28,
      fault_cases:12,fault_outcomes_correct:12,benign_count:12,benign_uninterrupted:10,
      false_financial_interventions:0,unauthorized_effects:0,duplicate_logical_effects:0,
      incorrect_final_states:2,model_cost_microdollars:101625,
      median_containment_seconds:15.8,p95_containment_seconds:17.9},
    limitations:['Reasoning by a live OpenAI model (gpt-5.6-luna); provider actions are the synthetic stateful world, not live providers.']
  }]}));
  await page.goto('/evaluations');
  await expect(page.getByRole('heading',{name:'Live-model reliability run'})).toBeVisible();
  await expect(page.getByTestId('reasoning-badge')).toContainText('LIVE MODEL');
  await expect(page.getByTestId('reasoning-badge')).toContainText('gpt-5.6-luna');
  await expect(page.getByTestId('correct-outcomes')).toContainText('46 / 48');
  await expect(page.getByTestId('model-cost')).toContainText('$0.10');
  await expect(page.getByText(/live OpenAI model/i)).toBeVisible();
});

test('an invalid token leaves the form available for retry', async ({ page }) => {
  await page.route('**/api/episodes', route => route.fulfill({status:401,json:{detail:'locked'}}));
  await page.route('**/api/session', route => route.fulfill({status:401,json:{detail:'invalid'}}));
  await page.goto('/app');
  await page.getByLabel('Local operator token').fill('incorrect');
  await page.getByRole('button',{name:'Unlock workspace'}).click();
  await expect(page.getByText('Token not accepted')).toBeVisible();
  await expect(page.getByLabel('Local operator token')).toBeVisible();
});

test('workspace displays actual returned episode and local proof', async ({ page }) => {
  await page.route('**/api/episodes', route => route.fulfill({json:[{id:'sc-demo',state:'CONTAINED'}]}));
  await page.route('**/api/episodes/sc-demo', route => route.fulfill({json:{id:'sc-demo',state:'CONTAINED',events:[],edges:[],agent_trace:[]}}));
  await page.route('**/api/reports', route => route.fulfill({json:[{episode_id:'sc-demo',mode:'local',reasoning_mode:'deterministic_fixture',episode_state:'CONTAINED',world:{pi_scam:'canceled',pi_unrelated:'requires_confirmation'},actions:[]}]}));
  await page.goto('/app');
  await expect(page.getByText('sc-demo',{exact:true})).toBeVisible();
  await expect(page.getByTestId('payment-unrelated')).toContainText('requires_confirmation');
});

test('workspace displays persisted model budget without implying a live model run', async ({ page }) => {
  await page.route('**/api/episodes', route => route.fulfill({json:[]}));
  await page.route('**/api/reports', route => route.fulfill({json:[]}));
  await page.route('**/api/usage', route => route.fulfill({json:{
    mode:'local',fresh_model_enabled:false,currency:'USD',model:{
      limit_microdollars:3_000_000,spent_microdollars:125_000,
      reserved_microdollars:400_000,available_microdollars:2_475_000
    }
  }}));

  await page.goto('/app');

  await expect(page.getByTestId('usage-panel')).toContainText('$0.125 measured');
  await expect(page.getByTestId('usage-panel')).toContainText('$0.400 reserved');
  await expect(page.getByTestId('usage-panel')).toContainText('$2.475 available');
  await expect(page.getByTestId('usage-panel')).toContainText('Fresh model disabled');
});

test('workspace renders the agent decision trace and causal chain', async ({ page }) => {
  await page.route('**/api/episodes', route => route.fulfill({json:[{id:'sc-demo',state:'CONTAINED'}]}));
  await page.route('**/api/reports', route => route.fulfill({json:[{episode_id:'sc-demo',mode:'local',reasoning_mode:'deterministic_fixture',episode_state:'CONTAINED',world:{pi_scam:'canceled',pi_unrelated:'requires_confirmation'},actions:[]}]}));
  await page.route('**/api/episodes/sc-demo', route => route.fulfill({json:{
    id:'sc-demo', state:'CONTAINED',
    events:[{event_id:'sc-demo:scam_call',provider:'twilio',payload:{resource_id:'scam_call'}},{event_id:'sc-demo:scam_message',provider:'telegram',payload:{resource_id:'scam_message'}}],
    edges:[{source_id:'sc-demo:scam_call',target_id:'sc-demo:scam_message',kind:'channel_migration'}],
    agent_trace:[
      {index:0,phase:'observe',summary:'Observed twilio scam_call',data:{}},
      {index:1,phase:'reason',summary:'1/3 markers; insufficient to intervene',data:{}},
      {index:2,phase:'decide',summary:'Policy authorized 4 scoped action(s)',data:{}},
      {index:3,phase:'verify',summary:'Re-read provider state after intervention',data:{}},
      {index:4,phase:'stop',summary:'Episode CONTAINED',data:{state:'CONTAINED'}}
    ]
  }}));
  await page.goto('/app');
  await expect(page.getByTestId('agent-trace')).toBeVisible();
  await expect(page.getByText('Policy authorized 4 scoped action(s)')).toBeVisible();
  await expect(page.getByText('channel migration')).toBeVisible();
  await expect(page.getByText('twilio·scam_call')).toBeVisible();
});

test('workspace runs the clearly labeled isolated local Hunter after containment', async ({ page }) => {
  await page.route('**/api/episodes', route => route.fulfill({json:[{id:'sc-demo',state:'CONTAINED'}]}));
  await page.route('**/api/episodes/sc-demo', route => route.fulfill({json:{id:'sc-demo',state:'CONTAINED',events:[],edges:[],agent_trace:[]}}));
  await page.route('**/api/reports', route => route.fulfill({json:[{episode_id:'sc-demo',mode:'local',reasoning_mode:'deterministic_fixture',episode_state:'CONTAINED',world:{pi_scam:'canceled',pi_unrelated:'requires_confirmation'},actions:[]}]}));
  await page.route('**/api/session', route => route.fulfill({json:{csrf_token:'csrf-test'}}));
  await page.route('**/api/local-hunter/sc-demo', route => route.fulfill({json:{state:'completed',sent_messages:1,indicators:[{kind:'domain',value:'pay.example.test',claim_status:'attacker_supplied'}]}}));
  await page.goto('/app');
  await page.getByRole('button',{name:'Run isolated Hunter fixture'}).click();
  await expect(page.getByText('pay.example.test',{exact:true})).toBeVisible();
  await expect(page.getByText('attacker supplied',{exact:true})).toBeVisible();
});
