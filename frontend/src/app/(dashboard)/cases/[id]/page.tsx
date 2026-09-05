"use client";

import { useParams } from "next/navigation";
import { useState } from "react";

import { CaseStatusBadge } from "@/components/case-status-badge";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { useAddComment, useCase, useCaseComments, useUpdateCase } from "@/hooks/use-cases";
import type { CaseStatus } from "@/lib/types";

export default function CaseDetailPage() {
  const params = useParams<{ id: string }>();
  const { data: caseData, isLoading } = useCase(params.id);
  const { data: comments = [] } = useCaseComments(params.id);
  const updateCase = useUpdateCase(params.id);
  const addComment = useAddComment(params.id);
  const [commentText, setCommentText] = useState("");

  if (isLoading || !caseData) {
    return <p className="text-sm text-muted-foreground">Loading...</p>;
  }

  function handleCommentSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!commentText.trim()) return;
    addComment.mutate(commentText, { onSuccess: () => setCommentText("") });
  }

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <CaseStatusBadge status={caseData.status} />
          <SeverityBadge severity={caseData.severity} />
        </div>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight">{caseData.title}</h1>
        {caseData.summary && (
          <p className="mt-1 text-sm text-muted-foreground">{caseData.summary}</p>
        )}
        {caseData.tags.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {caseData.tags.map((tag) => (
              <Badge key={tag} variant="outline">
                {tag}
              </Badge>
            ))}
          </div>
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Status</CardTitle>
        </CardHeader>
        <CardContent>
          <Select
            value={caseData.status}
            onValueChange={(v) => updateCase.mutate({ status: v as CaseStatus })}
          >
            <SelectTrigger className="w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="open">Open</SelectItem>
              <SelectItem value="investigating">Investigating</SelectItem>
              <SelectItem value="closed">Closed</SelectItem>
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      {caseData.alert_ids.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Linked Alerts</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1 text-sm text-muted-foreground">
              {caseData.alert_ids.map((id) => (
                <li key={id} className="font-mono text-xs">
                  {id}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Comments</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {comments.length === 0 ? (
            <p className="text-sm text-muted-foreground">No comments yet.</p>
          ) : (
            <div className="space-y-3">
              {comments.map((comment) => (
                <div key={comment.id}>
                  <p className="text-sm">{comment.body}</p>
                  <p className="text-xs text-muted-foreground">
                    {new Date(comment.created_at).toLocaleString()}
                  </p>
                </div>
              ))}
            </div>
          )}

          <Separator />

          <form onSubmit={handleCommentSubmit} className="flex gap-2">
            <Input
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
              placeholder="Add a comment..."
            />
            <Button type="submit" disabled={addComment.isPending}>
              Post
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
